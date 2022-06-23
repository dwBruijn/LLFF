import os
import subprocess
import time
import hashlib
import psutil
import requests
from datetime import date, timedelta
from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, send_from_directory

import config
import tools


app = Flask(__name__)

toolbox = dict({"chkrootkit": tools.Chkrootkit(), "find": tools.Find()})

@app.route("/")
def index():
    return redirect("/processes")


@app.route("/processes")
def procs():
    return render_template("processes.html"), 200


@app.route("/processes/list")
def processes_list():
    return jsonify({'data': list(filter(lambda pinfo: pinfo["pid"] != 2 and pinfo["ppid"] != 2,
                                        map(lambda pinfo: pinfo.as_dict(), psutil.process_iter())))}), 200


@app.route("/processes/<int:pid>/connections")
def process_connections(pid):
    return jsonify({"data": list(map(lambda pconn: pconn._asdict(), psutil.Process(pid).connections()))}), 200


@app.route("/processes/<int:pid>/core_file")
def process_gcore(pid):
    def dump(folder, pid):

        timestamp = str(int(time.time()))

        if not os.system(f"gcore -o {os.path.join(folder, timestamp)} {pid}"):
            for filename in os.listdir(folder):
                if filename.startswith(timestamp):
                    return filename

        return None

    CORE_FILES = "static/core_files"

    if not os.path.exists(CORE_FILES):
        os.mkdir(CORE_FILES)

    core_file = dump(CORE_FILES, pid)

    return send_from_directory(directory="static/core_files", filename=core_file, as_attachment=True)

# used to get memory segments in order to dump strings
@app.route("/processes/<int:pid>/memory_map")
def process_memory_map(pid):
    return jsonify(
        {"data": list(map(lambda pmmap_ext: pmmap_ext._asdict(), psutil.Process(pid).memory_maps(grouped=False)))}), 200


@app.route("/mem/<int:pid>/strings")
def mem_strings(pid):
    STRINGS = "static/strings"
    if not os.path.exists(STRINGS):
        os.mkdir(STRINGS)

    start = request.args.get("start", "")
    end = request.args.get("end", "")
    filename = "%s.%s_%s" % (pid, start, end)
    dump_file = os.path.join(STRINGS, filename + ".dmp")
    strings_file = os.path.join(STRINGS, filename + ".strs")

    def dump(pid, start, end, output_file):
        os.system(f"gdb --batch --pid {pid} -ex \"dump memory {output_file} 0x{start} 0x{end}\"")

    def strings(path, output_file):
        os.system(f"strings {path} > {output_file}")

    dump(pid, start, end, dump_file)
    strings(dump_file, strings_file)

    os.remove(dump_file)

    return send_from_directory(directory=STRINGS, filename=filename + ".strs", as_attachment=True)


@app.route("/fs/hash")
def fs_hash():
    md5 = hashlib.md5(open(request.args.get("path", ""), "rb").read()).hexdigest()
    sha256 = hashlib.sha256(open(request.args.get("path", ""), "rb").read()).hexdigest()

    return jsonify({"md5": md5, "sha256": sha256}), 200


@app.route("/fs/download")
def fs_download():
    return send_file(request.args.get("path", ""), as_attachment=True)


@app.route("/vt/report/<string:hash>")
def vt_report(hash):
    if not len(config.VT_APIKEY):
        return jsonify({"error": "NO API KEY"}), 200

    response = requests.get("https://www.virustotal.com/vtapi/v2/file/report", params={"apikey": config.VT_APIKEY, "resource": hash},
                            headers={"Accept-Encoding": "gzip, deflate", "User-Agent": "gzip,  LLFF"})

    return jsonify(response.json() if response.status_code == 200 else response.text), response.status_code


@app.route("/vt/upload")
def vt_upload():
    if not len(config.VT_APIKEY):
        return jsonify({"error": "NO API KEY"}), 200

    path = request.args.get("path", "")

    if not os.path.isfile(path):
        return jsonify({"error": f"{path} is not a valid file or the system could not access it"}), 200

    files = {"file": (os.path.basename(path), open(path, "rb"))}

    response = requests.post("https://www.virustotal.com/vtapi/v2/file/scan", params={"apikey": config.VT_APIKEY}, files=files,
                             headers={"Accept-Encoding": "gzip, deflate", "User-Agent": "gzip,  LLFF"})

    return jsonify(response.json() if response.status_code == 200 else response.text), response.status_code


@app.route("/users")
def users():
    return render_template("users.html"), 200


@app.route("/users/list")
def users_list():
    with open("/etc/passwd", "r") as f:
        users = list(map(lambda line: line.split(":"), f.readlines()))
    
    with open("/etc/shadow", "r") as f:
        shadow = list(map(lambda line: line.split(":"), f.readlines()))

    for u in users:
        for l in shadow:
            if u[0] == l[0]:
                if u[1] == "x":
                    # get password hash from shadow file
                    u[1] = l[1]
                if u[1] == "":
                    u[1] = "No Password"
                if u[1] == "*":
                    u[1] = "Disabled"
                if u[1] == "!" or u[1] == "!!" or u[1] == "!*":
                    u[1] = "Locked"

                # get password's last change date
                try:
                    l[2] = int(l[2])
                    if l[2] > 0:
                        last_changed = date(1970, 1, 1) + timedelta(l[2])
                        u.insert(2, last_changed.strftime("%d-%m-%Y"))
                    else:
                        u.insert(2, "-")
                except valueError:
                    u.insert(2, "-")

    return jsonify({"data": users}), 200

@app.route("/netstat")
def netstat():
    return render_template("netstat.html"), 200


@app.route("/netstat/raw")
def netstat_raw():
    return jsonify({"data": list(map(lambda sconn: sconn._asdict(), psutil.net_connections()))}), 200


@app.route("/logs/<string:file>")
def logs(file):
    if file == "system":
        log_path = "/var/log/syslog" if config.IS_UBUNTU else "/var/log/messages"

    elif file == "authentication":
        log_path = "/var/log/auth.log" if config.IS_UBUNTU else "/var/log/secure"

    elif file == "firewall":
        log_path = "/var/log/ufw.log" if config.IS_UBUNTU else "/var/log/firewalld"

    elif file == "bash":
        BASH_HISTORY = "static/bash_history"

        if not os.path.exists(BASH_HISTORY):
            os.mkdir(BASH_HISTORY)

        # handling the most common case (.bash_history)
        os.system("getent passwd | cut -d : -f 6 | sed 's:$:/.bash_history:' | xargs -d '\n' grep -s -H -e \"$pattern\" > " + BASH_HISTORY + "/complete_bash_history.log")

        log_path = BASH_HISTORY + "/complete_bash_history.log"
        
    else:
        abort(404)

    if os.path.isfile(log_path):
        with open(log_path, "r") as f:
            log_data = f.read()
    else:
        log_data = "- not found -"

    return render_template("logs.html", text=log_data), 200


@app.route("/services")
def services():
    proc = subprocess.Popen(["systemctl", "--type=service"], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()

    return render_template("services.html", text=out.decode("utf-8")), 200


@app.route("/tools/<string:tool>/run")
def tools_run(tool):
    if tool == "chkrootkit":
        toolbox["chkrootkit"].set_cmdline()
        toolbox["chkrootkit"].run()
    elif tool == "find":
        toolbox["find"].set_cmdline(request.args.get("dir", ""), request.args.get("name", ""))
        toolbox["find"].run()
    else:
        abort(404)

    return "", 200


@app.route("/tools/<string:tool>/status")
def tools_status(tool):
    if tool not in toolbox:
        abort(404)

    return toolbox[tool].status(), 200


@app.route("/tools/<string:tool>/results")
def tools_results(tool):
    if tool not in toolbox:
        abort(404)

    return toolbox[tool].results(), 200


@app.route("/tools/<string:tool>/stop")
def tools_stop(tool):
    if tool not in toolbox:
        abort(404)

    toolbox[tool].stop()

    return "", 200


@app.route("/files")
def files():
    return render_template("files.html"), 200


@app.route("/chkrootkit")
def chkrootkit():
    return render_template("chkrootkit.html"), 200


if __name__ == "__main__":
    app.run("127.0.0.1", 8080, debug=True)