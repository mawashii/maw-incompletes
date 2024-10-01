#!/usr/bin/env python3

import argparse
import os
import re
import time
import sqlite3
import subprocess
import logging
import yaml
import fnmatch
import pathlib
from pathlib import Path
from typing import List

sfv_clean = re.compile(r"^;.*$", flags=re.M)
sfv_pattern = re.compile(r"^\S+ [a-fA-F0-9]{8}$")

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s [%(levelname)7s] %(message)s"
)

class IncompleteChecker:
    def __init__(self, config, chain):
        self.glftpd_conf = Path(config["glftpd"]["conf"])
        self.glftpd_path = Path(config["glftpd"]["path"])
        self.glftpd_log = self.glftpd_path / config["glftpd"]["log"].lstrip("/")
        self.incompletes_db = Path(config["incompletes"]["db"])
        self.incompletes_path = self.glftpd_path / config["incompletes"]["path"].lstrip(
            "/"
        )
        self.config = config
        self.chain = chain

        self.conn = self.setup_db()
        self.users, self.groups = self.setup_userdb()
        self.dupelist = self.setup_dupelist()

        self.complete_re = re.compile(config["regex"]["complete"])
        self.daydir_re = re.compile(config["regex"]["daydir"])
        self.incomplete_re = re.compile(config["regex"]["incomplete"], re.I)
        self.nuke_re = re.compile(config["regex"]["nukes"], re.I)
        self.special_re = re.compile(
            config["regex"]["special"],
            re.I,
        )

    def setup_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.incompletes_db)
        conn.row_factory = sqlite3.Row
        with conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS Releases(id INTEGER PRIMARY KEY, timestamp INTEGER, release TEXT, path TEXT, incomplete INTEGER, approved INTEGER, processed INTEGER);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS `rlspath` ON `Releases` ( `release`, `path` );"
            )
        return conn

    def setup_userdb(self) -> (dict, dict):
        group_file = self.glftpd_path / "etc" / "group"
        passwd_file = self.glftpd_path / "etc" / "passwd"
        users = dict()
        groups = dict()
        with passwd_file.open("r") as f:
            for line in f:
                data = line.split(":")
                users[int(data[2])] = data[0]
        with group_file.open("r") as f:
            for line in f:
                data = line.split(":")
                groups[int(data[2])] = data[0]
        return users, groups

    def setup_dupelist(self) -> set:
        dupelist_bin = self.glftpd_path / "bin" / "dupelist"
        sp = subprocess.run(
            [dupelist_bin],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return {line.split()[0] for line in sp.stdout.splitlines()}

    @staticmethod
    def parse_sfv(sfv_path: Path) -> [str]:
        with sfv_path.open("r") as fp:
            content = fp.readlines()
            sfv_content = [sfv_clean.sub("", line) for line in content]
            sfv_lines = [s.strip() for s in sfv_content if s.strip()]
            filenames = []

            for line in sfv_lines:
                if not sfv_pattern.match(line):
                    return []
                else:
                    filenames.append(line.split()[0].lower())
        return filenames

    @staticmethod
    def get_release_age(path: Path) -> float:
        stat = path.stat()
        return min(stat.st_mtime, stat.st_ctime)

    def fix_check(self, path: Path, release: str) -> bool:
        check = release
        for char in ["_", "-", "."]:
            check = check.replace(char, "*")
        check = re.sub(r"\*+", "*", check)
        for dirpath in path.glob(check):
            if self.special_re.search(dirpath.name):
                if (
                    release.split("-")[-1].lower()
                    == dirpath.name.split("-")[-1].lower()
                ):
                    return True
        return False

    def get_chroot_path(self, release_path: Path) -> Path:
        chroot_path = str(release_path).replace(str(self.glftpd_path), "")
        return Path(chroot_path)

    def path_in_config(self, path: Path, key: str):
        return any([x in str(path) for x in self.config["glftpd"].get(key, [])])

    def write_log(self, message):
        timestamp = time.strftime("%a %b %d %T %Y", time.gmtime())
        try:
            with self.glftpd_log.open("a") as logf:
                logf.write(f'{timestamp} {self.chain}: "{message}"\n')
        except IOError:
            print(f"unable to write to glftpd log: {self.glftpd_log}")

    def nuke_dir(self, release_path: Path):
        nuker_bin = self.glftpd_path / "bin" / "nuker"
        chroot_path = self.get_chroot_path(release_path)
        logging.info(f"Nuking {release_path.name}")
        subprocess.run(
            [
                nuker_bin,
                "-r",
                self.glftpd_conf,
                "-N",
                "glftpd",
                "-n",
                "{%s}" % chroot_path,
                "3",
                "incomplete",
            ],
        )
        return True

    def undupe(self, release_path: Path, release_file: str):
        if release_file not in self.dupelist:
            return True

        undupe_bin = self.glftpd_path / "bin" / "undupe"
        logging.info(f"Triggering undupe for {release_path.name}/{release_file}")
        subprocess.run(
             [undupe_bin, "-r", self.glftpd_conf, "-f", release_file],
        )
        return True

    def rescan(self, release_path: Path):
        rescan_bin = self.glftpd_path / "bin" / "rescan"
        chroot_path = self.get_chroot_path(release_path)
        pzs_root = self.glftpd_path / "ftp-data" / "pzs-ng"
        pzs_path = pzs_root / str(chroot_path).lstrip("/")
        headdata_path = pzs_path / "headdata.lock"

        if pzs_path.is_dir() and headdata_path.is_file():
            logging.info(f"Removing headdata files in {pzs_path}")
            for file in pzs_path.glob("headdata*"):
                file.unlink()

        logging.info(f"Triggering rescan for {chroot_path}")
        subprocess.run(
            [
                rescan_bin,
                "--quick",
                f"--chroot={self.glftpd_path}",
                f"--dir={chroot_path}",
            ],
        )
        return True

    def get_dirs(self, path: Path) -> [Path]:
        dirs = []
        for dirpath in path.iterdir():
            if not dirpath.is_dir() or dirpath.is_symlink():
                 continue
            if self.daydir_re.match(dirpath.name):
                 for subdir in dirpath.iterdir():
                     if subdir.is_dir():
                         for moar in subdir.iterdir():
                             if subdir.is_dir() and not self.complete_re.match(subdir.name):
                                 dirs += self.get_dirs(moar)

            elif self.nuke_re.match(dirpath.name):
                continue
            elif self.path_in_config(dirpath, "skip_paths"):
                continue
            else:
                dirs.append(dirpath)
        return dirs

    def get_user_group(self, uid: int, gid: int) -> (str, str):
        user = self.users.get(uid, "unknown")
        group = self.groups.get(gid, "unknown")
        return user, group

    def run(self) -> List[str]:
        paths = []
        messages = []

        for section_path in config["glftpd"]["section_paths"]:
            section_path = self.glftpd_path / section_path.lstrip("/")
            paths += self.get_dirs(section_path)

        for path in sorted(paths):
            site_path, release, reasons, user, group = self.check_release(path)
            if len(reasons):
                message = f"    {site_path}/\002{release}\002 lacks \002{'/'.join(reasons)}\002, was sent by \002{user}\002/{group}"
                messages.append(message)

        for path in self.incompletes_path.iterdir():
            if path.is_symlink() and not path.is_dir():
                path.unlink()

        return messages

    def check_release(self, release_path: Path) -> (str, str, [str], str, str):
        reasons = []
        release = release_path.name
        dirpath = release_path.parent
        chroot_path = str(self.get_chroot_path(release_path).parent)
        dirpath_announce = chroot_path.replace("/site", "")
        link_path = self.incompletes_path / release

        if (time.time() - self.get_release_age(release_path)) < 60:
            return dirpath_announce, release, reasons, "", ""

        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT id, incomplete, approved, processed FROM Releases WHERE release=? AND path=?;",
                (release, chroot_path),
            )
            release_info = cursor.fetchone()
            if release_info:
                if release_info["processed"] == 1:
                    if link_path.is_symlink():
                        link_path.unlink()
                    return dirpath_announce, release, reasons, "", ""
                if release_info["incomplete"] == 0 or release_info["approved"] == 1:
                    if link_path.is_symlink():
                        link_path.unlink()
                    self.conn.execute(
                        "UPDATE Releases SET timestamp=?, processed=? WHERE id=?;",
                        (int(time.time()), 1, release_info["id"]),
                    )
                    return dirpath_announce, release, reasons, "", ""

        if self.special_re.search(release):
            with self.conn:
                self.conn.execute(
                    "INSERT INTO Releases (timestamp, release, path, incomplete, approved, processed) VALUES (?, ?, ?, ?, ?, ?);",
                    (int(time.time()), release, chroot_path, 0, 0, 1),
                )
            return dirpath_announce, release, reasons, "", ""

        try:
            dir_info = release_path.stat()
        except OSError:
            return dirpath_announce, release, reasons, "", ""
        uid = dir_info.st_uid
        gid = dir_info.st_gid

        logging.info(f"Checking out {release} in {chroot_path}")

        nfo = 0
        sample = 0
        zips = 0
        complete_dirs = []

        rescanned = False
        for path, subdirs, files in os.walk(release_path):
            path = Path(path)
            is_complete = None
            is_root = path == release_path
            sfv = 0
            subdir_name = path.name.lower()
            files_lc = [f.lower() for f in files]

            for entry in subdirs + files:
                if self.complete_re.search(entry):
                    is_complete = True
                    complete_dirs.append(path)
                elif self.incomplete_re.search(entry):
                    is_complete = False
                    complete_dirs.append(path)
                    if is_root:
                        reasons.append("is currently incomplete!")
                    else:
                        reasons.append(f"/{subdir_name} appears to be incomplete!")

            if is_root or subdir_name in ["subs"]:
                for file in [path / f for f in files]:
                    if file.suffix.lower() == ".nfo":
                        if is_root:
                            nfo += 1
                        else:
                            file.unlink()
                    elif file.suffix.lower() == ".sfv":
                        sfv += 1
                        if is_complete:
                            release_files = self.parse_sfv(file)
                            for release_file in release_files:
                                if release_file not in files_lc:
                                    is_complete = False
                                    break
                    elif file.suffix.lower() == ".diz":
                        sfv += 1
                    elif file.suffix.lower() == ".zip" and is_root:
                        zips += 1
                    elif file.suffix.lower().endswith("-missing"):
                        self.undupe(path, file.name.replace("-missing", ""))

                if is_root and nfo == 0 and not self.fix_check(dirpath, release):
                    reasons.append("missing the \037nfo\037!")
                if is_root and sfv == 0 and not any(fnmatch.fnmatch(release, pattern) for pattern in ["*COMPLETE*"]):
                   reasons.append("missing the \037sfv\037!")
                elif not is_root and sfv == 0:
                    reasons.append(subdir_name)

            elif subdir_name == "sample":
                for file in [path / f for f in files]:
                    if file.suffix.lower() in (".avi", ".m2ts", ".mkv", ".mp4", ".vob", ".wmv"):
                        sample += 1
                    elif file.suffix.lower() in (".jpeg", ".jpg", ".png"):
                        continue
                    else:
                        logging.debug(
                            f"Found {file.name} in {path} which appears to be junk, clean up"
                        )

            elif subdir_name == "proof":
                proof = 0
                for file in [path / f for f in files]:
                    if file.suffix.lower() in (
                        ".jpeg",
                        ".jpg",
                        ".m2ts",
                        ".png",
                        ".rar",
                        ".vob",
                    ):
                        proof += 1
                if proof == 0 and not self.fix_check(dirpath, release):
                    reasons.append("\037empty\037 proof dir!")

            if sfv > 0 and path not in complete_dirs:
                self.rescan(path)
                rescanned = True
            elif is_root and zips > 0 and sfv == 0:
                self.rescan(path)
                rescanned = True

            if is_complete is not None and not is_complete and not rescanned:
                logging.info(f"Rescanning {path} because it is incomplete!")
                self.rescan(path)
                rescanned = True

        if (
            sample == 0
            and not self.fix_check(dirpath, release)
            and not self.path_in_config(dirpath, "no_sample_paths")
        ):
            reasons.append("sample")
        user, group = self.get_user_group(uid, gid)
        if len(reasons):
            if self.path_in_config(dirpath, "mask_userinfo_paths"):
                user = config["glftpd"]["mask_user"]
                group = config["glftpd"]["mask_group"]

            if self.path_in_config(dirpath, "nuke_on_inc_paths"):
                self.nuke_dir(release_path)
                return dirpath_announce, release, reasons, user, group

            if not link_path.is_symlink():
                os.symlink("..%s/%s" % (dirpath_announce, release), link_path)
            if link_path.is_symlink() and not link_path.is_dir():
                link_path.unlink()
                os.symlink("..%s/%s" % (dirpath_announce, release), link_path)
        else:
            if link_path.is_symlink():
                link_path.unlink()

        if rescanned or len(reasons):
            incomplete = 1
            processed = 0
        else:
            incomplete = 0
            processed = 1

        with self.conn:
            if release_info is None:
                self.conn.execute(
                    "INSERT INTO Releases (timestamp, release, path, incomplete, approved, processed) VALUES (?, ?, ?, ?, ?, ?);",
                    (int(time.time()), release, chroot_path, incomplete, 0, processed),
                )
            else:
                self.conn.execute(
                    "UPDATE Releases SET timestamp=?, incomplete=? WHERE id=?;",
                    (int(time.time()), incomplete, release_info["id"]),
                )

        return dirpath_announce, release, reasons, user, group

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("config", help="path to config file")
    parser.add_argument(
        "chain", help="the output destination of this announce", default=None
    )
    parser.add_argument("--silent", help="no output to glftpd.log", action="store_true")
    args = parser.parse_args()

    script_path = Path(__file__).resolve().parent
    with (script_path / args.config).open() as f:
        config = yaml.safe_load(f)

    chain = args.chain if args.chain else config["chain"]
    if not re.search(r"^[a-zA-Z0-9]+$", chain):
        print(            f"ERROR: You need to provide a valid output chain - provided chain {chain} is invalid"
        )
        exit(1)

    checker = IncompleteChecker(config, chain)
    messages = checker.run()

    if args.silent:
        for message in messages:
            logging.info(message)
    elif len(messages):
        for message in messages:
            lines = message.split('\n')
            for line in lines:
                checker.write_log(line)
