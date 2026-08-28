import argparse
import os
import stat
import sys

import paramiko


HOST = os.environ.get("PVE_HOST", "202.189.4.217")
PORT = int(os.environ.get("PVE_PORT", "60022"))
USER = os.environ.get("PVE_USER", "root")
PASSWORD = os.environ["PVE_PASSWORD"]


def connect():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        HOST,
        port=PORT,
        username=USER,
        password=PASSWORD,
        timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run(args):
    client = connect()
    try:
        stdin, stdout, stderr = client.exec_command(args.command, get_pty=args.pty)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        if out:
            print(out, end="")
        if err:
            print(err, end="", file=sys.stderr)
        sys.exit(stdout.channel.recv_exit_status())
    finally:
        client.close()


def put(args):
    client = connect()
    try:
        sftp = client.open_sftp()
        sftp.put(args.local, args.remote)
        if args.mode:
            sftp.chmod(args.remote, int(args.mode, 8))
        sftp.close()
    finally:
        client.close()


def get(args):
    client = connect()
    try:
        sftp = client.open_sftp()
        sftp.get(args.remote, args.local)
        sftp.close()
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(required=True)

    run_parser = sub.add_parser("run")
    run_parser.add_argument("command")
    run_parser.add_argument("--pty", action="store_true")
    run_parser.set_defaults(func=run)

    put_parser = sub.add_parser("put")
    put_parser.add_argument("local")
    put_parser.add_argument("remote")
    put_parser.add_argument("--mode")
    put_parser.set_defaults(func=put)

    get_parser = sub.add_parser("get")
    get_parser.add_argument("remote")
    get_parser.add_argument("local")
    get_parser.set_defaults(func=get)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
