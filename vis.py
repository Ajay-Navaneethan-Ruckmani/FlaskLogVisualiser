from flask import Flask, render_template, send_file
import json
from path import Path
import matplotlib.pyplot as plt
import io

# Configuration
log_path = '/home/cowrie/cowrie/var/log/cowrie'
bind_host = '0.0.0.0'
bind_port = 5000

app = Flask(__name__)

@app.route('/')
def index():
    return render_log('cowrie.json')

@app.route('/plot')
def plot():
    # Extract data from logs
    ssh_attempts, telnet_attempts, successful_logins, failed_logins, commands_executed = extract_data_from_logs()

    categories = ["SSH Attempts", "Telnet Attempts", "Successful Logins", "Failed Logins", "Commands Executed"]
    values = [ssh_attempts, telnet_attempts, successful_logins, failed_logins, commands_executed]

    plt.figure(figsize=(10, 6))
    plt.bar(categories, values)
    plt.xlabel('Activity Type')
    plt.ylabel('Count')
    plt.title('Honeypot Activity Overview')

    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    return send_file(img, mimetype='image/png')

@app.route('/visualization')
def visualization():
    return render_template('visualization.html', page='visualization')


def extract_data_from_logs():
    ssh_attempts = 0
    telnet_attempts = 0
    successful_logins = 0
    failed_logins = 0
    commands_executed = 0

    with open(log_path + '/cowrie.json', 'r') as f:
        for line in f:
            log = json.loads(line)
            # Assuming the log structure contains these fields. Adjust as per actual log structure.
            if log.get('protocol') == 'ssh':
                ssh_attempts += 1
            if log.get('protocol') == 'telnet':
                telnet_attempts += 1
            if log.get('eventid') == 'cowrie.login.success':
                successful_logins += 1
            if log.get('eventid') == 'cowrie.login.failed':
                failed_logins += 1
            if log.get('eventid') == 'cowrie.command.input':
                commands_executed += 1

    return ssh_attempts, telnet_attempts, successful_logins, failed_logins, commands_executed

def get_log_files():
    files = []
    d = Path(log_path)
    for f in d.files('*.json*'):
        files.append(f.name)
    return sorted(files)

def render_log(current_logfile):
    logfiles = get_log_files()
    data = []
    with open(log_path + '/' + current_logfile) as f:
        for line in f:
            j = json.loads(line)
            data.append(j)
    return render_template('index.html', json=data, logfiles=logfiles, current_logfile=current_logfile)

@app.route('/stats/userpass')
def show_stats_userpass():
    usernames, passwords = extract_userpass()
    return render_template('stats_userpass.html', usernames=usernames, passwords=passwords)

def extract_userpass():
    usernames = {}
    passwords = {}
    with open(log_path + '/cowrie.json', 'r') as f:
        for line in f:
            log = json.loads(line)
            if 'username' in log:
                usernames[log['username']] = usernames.get(log['username'], 0) + 1
            if 'password' in log:
                passwords[log['password']] = passwords.get(log['password'], 0) + 1
    sorted_usernames = sorted(usernames.items(), key=lambda x: x[1], reverse=True)
    sorted_passwords = sorted(passwords.items(), key=lambda x: x[1], reverse=True)
    return sorted_usernames, sorted_passwords

if __name__ == '__main__':
    app.run(host=bind_host, port=bind_port)
