#!/usr/bin/env python3
# Import datasets to Elasticsearch or logstash instance

import sys
import json
import tarfile
import requests
from argparse import ArgumentParser
from pathlib import Path
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, TransferSpeedColumn
from rich.console import Console
from termcolor import colored

console = Console()

# Argument parsing
argparser = ArgumentParser(description="Import datasets into Elasticsearch or Logstash")
argparser.add_argument("--output", "-o", choices=["elasticsearch", "logstash"], default="elasticsearch", help="Choose Elasticsearch or Logstash as output")
argparser.add_argument("--recursive", "-r", action="store_true", help="Recurse into directories")
argparser.add_argument("--url", "-u", default="http://localhost:9200", help="URL of Elasticsearch or Logstash")
argparser.add_argument("--cacerts", "-c", default=None, help="Path to CA certificates for TLS verification")
argparser.add_argument("--insecure", "-I", dest="verify_certs", action="store_false", help="Disable TLS certificate verification")
argparser.set_defaults(verify_certs=True)
argparser.add_argument("--index", "-i", default="winlogbeat-mordor", help="Target index for data import")
argparser.add_argument("--no-index-creation", "-n", dest="create_index", action="store_false", help="Don't create the index")
argparser.set_defaults(create_index=True)
argparser.add_argument("inputs", nargs="+", type=Path, help="Path to dataset")

args = argparser.parse_args()

# Setup Elasticsearch or Logstash
if args.output == "elasticsearch":
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import bulk

    console.print("[cyan]Initializing Elasticsearch...[/cyan]")
    es = Elasticsearch(
        [args.url],
        ca_certs=args.cacerts,
        verify_certs=args.verify_certs
    )
    if args.create_index:
        if not es.indices.exists(index=args.index):
            es.indices.create(index=args.index, body={"settings": {"index.mapping.total_fields.limit": 2000}})
elif args.output == "logstash":
    console.print("[cyan]Initializing Logstash...[/cyan]")
    if args.verify_certs and args.cacerts:
        verify_certs = args.cacerts
    elif not args.verify_certs:
        from urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        verify_certs = False
    else:
        verify_certs = True
    logstash_url = args.url
else:
    console.print("[red]Output type not recognized. Exiting...[/red]")
    sys.exit(1)

# Collect input paths
if args.recursive:
    paths = [p for path in args.inputs for p in path.rglob("*.tar.gz") if p.is_file()]
else:
    paths = [path for path in args.inputs if path.is_file()]

console.print("[cyan]Calculating total file size...[/cyan]")
total_size = sum([
    member.size
    for path in paths
    for member in tarfile.open(path, mode="r:gz").getmembers() if member.isfile()
])

def generate_actions(fileobj, logfile_path, progress_task, progress):
    for line in fileobj:
        source = json.loads(line)
        source["log"] = {"file": {"name": logfile_path}}
        source.setdefault("winlog", {})

        if "EventID" in source:
            source["winlog"]["event_id"] = source.pop("EventID", None)
            source.pop("type", None)
            source.pop("host", None)

            source["winlog"]["event_data"] = {
                k: v for k, v in source.items()
                if k not in ("winlog", "log", "Channel", "Hostname", "@timestamp", "@version")
            }
            for k in list(source["winlog"]["event_data"].keys()):
                source.pop(k, None)

            source["winlog"]["computer_name"] = source.pop("Hostname", source.get("winlog", {}).get("computer_name", None))
            source["winlog"]["channel"] = source.pop("Channel", source.get("winlog", {}).get("channel", None))

        if "event_data" in source:
            source["winlog"]["event_data"] = source.pop("event_data")

        if "log_name" in source:
            source["winlog"]["channel"] = source.pop("log_name")

        if source.get("winlog", {}).get("channel", "") == "security":
            source["winlog"]["channel"] = "Security"

        if "event_id" in source:
            source["winlog"]["event_id"] = source.pop("event_id")

        source.setdefault("event", {})["code"] = source["winlog"].get("event_id")

        progress.update(progress_task, advance=len(line))

        if args.output == "elasticsearch":
            yield {"_index": args.index, "_source": source}
        elif args.output == "logstash":
            yield source

# Main import loop
total_success = 0
total_failed = 0

with Progress(
    TextColumn("[progress.description]{task.description}"),
    BarColumn(),
    TransferSpeedColumn(),
    "[progress.percentage]{task.percentage:>3.1f}%",
    TimeElapsedColumn(),
    TimeRemainingColumn(),
    transient=True
) as progress:
    transfer = progress.add_task("Importing logs...", total=total_size)

    for path in paths:
        console.print(f"[green]Processing:[/green] {path}")
        with tarfile.open(path, mode="r:gz") as tf:
            for member in tf.getmembers():
                if member.isfile():
                    logfile = f"{path}/{member.name}"
                    console.print(f"- [blue]Extracting {member.name}[/blue]")
                    mf = tf.extractfile(member)

                    if args.output == "elasticsearch":
                        success_count, fail_count = bulk(es, generate_actions(mf, logfile, transfer, progress), stats_only=True)
                        total_success += success_count
                        total_failed += fail_count
                        color = "green" if fail_count == 0 else "red"
                    elif args.output == "logstash":
                        success_count = fail_count = 0
                        for event in generate_actions(mf, logfile, transfer, progress):
                            r = requests.post(logstash_url, json=event, verify=verify_certs)
                            if r.status_code == 200:
                                success_count += 1
                                total_success += 1
                            else:
                                fail_count += 1
                                total_failed += 1
                        color = "green" if fail_count == 0 else "red"
                    console.print(colored(f"- Imported {success_count} events, {fail_count} failed", color))

console.print(f"[bold green]Done:[/bold green] Imported {total_success} records, [red]{total_failed} failed.[/red]")
