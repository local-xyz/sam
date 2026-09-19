export function reviewTools(rows, service) {
  return rows.filter(row => row.peer_id && row.tool_name === `mcp://${service}/review_code`);
}
