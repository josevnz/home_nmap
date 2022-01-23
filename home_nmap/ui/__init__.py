from typing import Any

from rich.align import Align
from rich.layout import Layout
from rich.progress import Progress, TaskID
from rich.table import Table

from home_nmap.query import NDISHtml


def create_scan_table(*, cli: str) -> Table:
    """
    Create a table for the CLI UI
    :param cli: Full Nmap arguments used on the run
    :return: Skeleton table, no data
    """
    nmap_table = Table(title=f"NMAP run info: {cli}")
    nmap_table.add_column("IP", justify="right", style="cyan", no_wrap=True)
    nmap_table.add_column("Protocol", justify="right", style="cyan", no_wrap=True)
    nmap_table.add_column("Port ID", justify="right", style="magenta", no_wrap=True)
    nmap_table.add_column("Service", justify="right", style="green")
    nmap_table.add_column("CPE", justify="right", style="blue")
    nmap_table.add_column("Advisories", justify="right", style="blue")
    return nmap_table


def update_scan_table(
        *,
        scan_result: Any,
        results_table: Table,
        main_layout: Layout,
        progress: Progress,
        task_id: TaskID,
        full_advisory: bool = False
) -> None:
    progress.advance(task_id, 1.0)
    ndis = NDISHtml()
    for host_data in scan_result:
        address = host_data['address']
        for port_data in host_data['ports']:
            service_info = (
                f"{port_data['service_name'].strip()} "
                f"{port_data['service_product'].strip()} "
                f"{port_data['service_version'].strip()}"
            )
            advisories = []  # Service CPE may not have an advisory
            for cpe in port_data['cpes']:
                progress.update(
                    task_id,
                    description=f"[yellow]Getting details for CPE: [bold]{cpe}[/yellow][/bold] :ok:",
                    advance=1.0
                )
                raw_ndis = ndis.get(cpe)
                nids_list = ndis.parse(raw_ndis)
                for nids in nids_list:
                    if full_advisory:
                        advisories.append(
                            f"[bold][yellow]link={nids.link}[/yellow][/bold], "
                            f"{nids.summary}, "
                            f"[red]score={nids.score}[/red]"
                        )
                    else:
                        advisories.append(
                            f"[bold][yellow]link={nids.link}[/yellow][/bold], "
                            f"[red]score={nids.score}[/red]"
                        )
            results_table.add_row(
                address,
                port_data['protocol'],
                port_data['port_id'],
                service_info,
                "\n".join(port_data['cpes']),
                "\n".join(advisories)
            )
    main_layout['Scan results'].update(
        Align.center(
            results_table,
            vertical="top"
        )
    )


def fill_simple_table(*, exec_data: str, parsed_xml: list[dict[Any, Any]]) -> Table:
    """
    Convenience method to create a simple UI table with Nmap XML output
    :param exec_data: Arguments and options used to run Nmap
    :param parsed_xml: Nmap data as a dictionary
    :return: Populated tabled
    """
    cpe_details = NDISHtml().correlate_nmap_with_nids(parsed_xml)
    nmap_table = create_scan_table(cli=exec_data)
    for row_data in parsed_xml:
        address = row_data['address']
        ports = row_data['ports']
        for port_data in ports:
            advisories = []
            for cpe in port_data['cpes']:
                if cpe in cpe_details:  # Service may not have an advisory
                    for nids in cpe_details[cpe]:
                        advisories.append(
                            f"[bold][yellow]link={nids.link}[/yellow][/bold], "
                            f"{nids.summary}, [red]score={nids.score}[/red]"
                        )
            nmap_table.add_row(
                address,
                port_data['protocol'],
                port_data['port_id'],
                f"{port_data['service_name']} {port_data['service_product']} {port_data['service_version']}",
                "\n".join(port_data['cpes']),
                "\n".join(advisories)
            )
    return nmap_table
