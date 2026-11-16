"""
PCAP / PCAPNG file loading using scapy.

Handles RadioTap/802.11 captures (link-type 127) which scapy's ``rdpcap``
dissects correctly via the RadioTap / Dot11 layer stack.

Error handling contract
-----------------------
- ``FileNotFoundError`` → file does not exist on disk.
- ``PcapReadError``     → file exists but cannot be parsed (wrong format,
                           truncated header, etc.).
- Non-fatal issues (e.g. a single truncated packet) are collected in the
  returned ``warnings`` list rather than raising an exception.
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

from scapy.packet import Packet

try:
    from scapy.all import rdpcap
    from scapy.error import Scapy_Exception
except ImportError as _exc:  # pragma: no cover
    raise ImportError(
        "scapy is required for PCAP loading.  "
        "Install it with: pip install scapy"
    ) from _exc


class PcapReadError(Exception):
    """Raised when a PCAP file exists but cannot be opened or parsed."""


def load_pcap(file_path: str) -> Tuple[List[Packet], List[str]]:
    """
    Load all packets from a PCAP or PCAPNG file.

    Parameters
    ----------
    file_path : str
        Path to the ``.pcap`` or ``.pcapng`` file.

    Returns
    -------
    packets : list[Packet]
        All packets from the file.  May be an empty list if the file
        was valid but contained zero packets.
    warnings : list[str]
        Non-fatal issues encountered (e.g. truncated packet at end of file).
        An empty list means a clean load.

    Raises
    ------
    FileNotFoundError
        If *file_path* does not exist on disk.
    PcapReadError
        If the file exists but cannot be parsed (wrong magic, bad header,
        zero-byte file, permission denied, etc.).
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {file_path!r}")

    if not path.is_file():
        raise PcapReadError(f"Path is not a regular file: {file_path!r}")

    if path.stat().st_size == 0:
        raise PcapReadError(f"PCAP file is empty (0 bytes): {file_path!r}")

    warnings: List[str] = []

    try:
        packets = rdpcap(str(path))
    except Scapy_Exception as exc:
        raise PcapReadError(
            f"scapy could not parse {file_path!r}: {exc}"
        ) from exc
    except PermissionError as exc:
        raise PcapReadError(
            f"Permission denied reading {file_path!r}: {exc}"
        ) from exc
    except Exception as exc:
        raise PcapReadError(
            f"Unexpected error reading {file_path!r}: {exc}"
        ) from exc

    packet_list = list(packets)

    if len(packet_list) == 0:
        warnings.append(
            f"File parsed successfully but contained 0 packets: {file_path!r}"
        )

    return packet_list, warnings
