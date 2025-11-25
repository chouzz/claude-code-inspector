"""
Stream merger utility for Claude-Code-Inspector.

Aggregates streaming response chunks into complete request-response pairs.
"""

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from cci.logger import get_logger
from cci.models import MergedRecord
from cci.storage import JSONLWriter, read_jsonl


class StreamMerger:
    """
    Merges streaming response chunks into complete records.

    Reads a JSONL file with interleaved request/response_chunk/response_meta
    records and produces a new file with merged request-response pairs.
    """

    def __init__(self, input_path: str | Path, output_path: str | Path):
        """
        Initialize the stream merger.

        Args:
            input_path: Path to input JSONL file with raw chunks
            output_path: Path to output JSONL file for merged records
        """
        self.input_path = Path(input_path)
        self.output_path = Path(output_path)
        self._logger = get_logger()

    def merge(self) -> dict[str, int]:
        """
        Perform the merge operation.

        Returns:
            Statistics about the merge operation
        """
        self._logger.info("Reading records from %s", self.input_path)
        records = read_jsonl(self.input_path)

        # Group records by request_id
        requests: dict[str, dict[str, Any]] = {}
        chunks: dict[str, list[dict[str, Any]]] = defaultdict(list)
        metas: dict[str, dict[str, Any]] = {}
        non_streaming: dict[str, dict[str, Any]] = {}

        for record in records:
            record_type = record.get("type", "")

            if record_type == "request":
                requests[record["id"]] = record
            elif record_type == "response_chunk":
                request_id = record.get("request_id")
                if request_id:
                    chunks[request_id].append(record)
            elif record_type == "response_meta":
                request_id = record.get("request_id")
                if request_id:
                    metas[request_id] = record
            elif record_type == "response":
                # Non-streaming response
                request_id = record.get("request_id")
                if request_id:
                    non_streaming[request_id] = record

        self._logger.info(
            "Found %d requests, %d chunks, %d non-streaming responses",
            len(requests),
            sum(len(c) for c in chunks.values()),
            len(non_streaming),
        )

        # Merge records
        merged_records: list[MergedRecord] = []
        stats = {
            "total_requests": len(requests),
            "streaming_requests": 0,
            "non_streaming_requests": 0,
            "incomplete_requests": 0,
            "total_chunks_processed": 0,
        }

        for request_id, request in requests.items():
            # Check if this was a streaming or non-streaming request
            if request_id in chunks:
                # Streaming request
                request_chunks = sorted(
                    chunks[request_id], key=lambda x: x.get("chunk_index", 0)
                )
                meta = metas.get(request_id, {})

                # Extract text from chunks
                response_text = self._extract_text_from_chunks(request_chunks)

                merged = MergedRecord(
                    request_id=request_id,
                    timestamp=self._parse_timestamp(request.get("timestamp")),
                    method=request.get("method", ""),
                    url=request.get("url", ""),
                    request_body=request.get("body"),
                    response_status=meta.get("status_code", request_chunks[0].get("status_code", 0))
                    if request_chunks
                    else 0,
                    response_text=response_text,
                    total_latency_ms=meta.get("total_latency_ms", 0),
                    chunk_count=len(request_chunks),
                )
                merged_records.append(merged)
                stats["streaming_requests"] += 1
                stats["total_chunks_processed"] += len(request_chunks)

            elif request_id in non_streaming:
                # Non-streaming request
                response = non_streaming[request_id]

                # Extract text from body
                body = response.get("body")
                if isinstance(body, dict):
                    response_text = self._extract_text_from_body(body)
                elif isinstance(body, str):
                    response_text = body
                else:
                    response_text = json.dumps(body) if body else ""

                merged = MergedRecord(
                    request_id=request_id,
                    timestamp=self._parse_timestamp(request.get("timestamp")),
                    method=request.get("method", ""),
                    url=request.get("url", ""),
                    request_body=request.get("body"),
                    response_status=response.get("status_code", 0),
                    response_text=response_text,
                    total_latency_ms=response.get("latency_ms", 0),
                    chunk_count=0,
                )
                merged_records.append(merged)
                stats["non_streaming_requests"] += 1

            else:
                # Request without response
                self._logger.warning("Request %s... has no response", request_id[:8])
                stats["incomplete_requests"] += 1

        # Write merged records
        self._logger.info("Writing %d merged records to %s", len(merged_records), self.output_path)

        with JSONLWriter(self.output_path) as writer:
            for record in merged_records:
                writer.write_record(record)

        return stats

    def _extract_text_from_chunks(self, chunks: list[dict[str, Any]]) -> str:
        """Extract the complete response text from streaming chunks."""
        text_parts: list[str] = []

        for chunk in chunks:
            content = chunk.get("content", {})
            if isinstance(content, dict):
                # Handle different API formats

                # Anthropic format
                if "delta" in content:
                    delta = content["delta"]
                    if isinstance(delta, dict) and "text" in delta:
                        text_parts.append(delta["text"])

                # OpenAI format
                if "choices" in content:
                    for choice in content.get("choices", []):
                        delta = choice.get("delta", {})
                        if "content" in delta:
                            text_parts.append(delta["content"])

                # Raw text in content
                if "text" in content:
                    text_parts.append(content["text"])

                # Message content
                if "content_block" in content:
                    block = content["content_block"]
                    if isinstance(block, dict) and "text" in block:
                        text_parts.append(block["text"])

            elif isinstance(content, str):
                text_parts.append(content)

        return "".join(text_parts)

    def _extract_text_from_body(self, body: dict[str, Any]) -> str:
        """Extract text from a non-streaming response body."""
        # Anthropic format
        if "content" in body:
            content = body["content"]
            if isinstance(content, list):
                texts = []
                for item in content:
                    if isinstance(item, dict) and "text" in item:
                        texts.append(item["text"])
                return "".join(texts)
            elif isinstance(content, str):
                return content

        # OpenAI format
        if "choices" in body:
            texts = []
            for choice in body.get("choices", []):
                message = choice.get("message", {})
                if "content" in message:
                    texts.append(message["content"])
            return "".join(texts)

        # Fallback: JSON dump
        return json.dumps(body)

    def _parse_timestamp(self, ts: Any) -> datetime:
        """Parse a timestamp from various formats."""
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            # Handle ISO format with Z suffix
            ts = ts.rstrip("Z")
            try:
                return datetime.fromisoformat(ts)
            except ValueError:
                pass
        return datetime.utcnow()


def merge_streams(input_path: str | Path, output_path: str | Path) -> dict[str, int]:
    """
    Convenience function to merge streaming chunks.

    Args:
        input_path: Path to input JSONL file
        output_path: Path to output JSONL file

    Returns:
        Statistics about the merge operation
    """
    merger = StreamMerger(input_path, output_path)
    return merger.merge()

