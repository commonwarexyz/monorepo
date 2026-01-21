#!/usr/bin/env node

/**
 * Integration test for the Commonware MCP server.
 *
 * This script:
 * 1. Tests CORS support
 * 2. Verifies server info via MCP protocol
 * 3. Triggers indexing and tests MCP tools
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const BASE_URL = process.env.MCP_URL || "http://localhost:8787";

async function triggerIndexing() {
  console.log("Triggering synchronous indexing...");

  // reindexVersions indexes one version per call, loop until we get one
  let indexed = null;
  while (indexed === null) {
    const response = await fetch(`${BASE_URL}/__test/reindex`);
    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Reindex failed: ${response.status} - ${body}`);
    }
    const result = await response.json();
    indexed = result.indexed;
    if (indexed) {
      console.log(`Indexed version: ${indexed}`);
    }
  }
  console.log("Indexing complete");
}

async function testCors() {
  console.log("Testing CORS support...");

  // Test OPTIONS preflight (handled by MCP handler's WorkerTransport)
  console.log("  Testing OPTIONS preflight...");
  const preflightResponse = await fetch(`${BASE_URL}/`, {
    method: "OPTIONS",
    headers: {
      Origin: "https://example.com",
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "Content-Type, mcp-session-id",
    },
  });
  if (preflightResponse.status !== 200 && preflightResponse.status !== 204) {
    throw new Error(`CORS preflight failed: expected 200/204, got ${preflightResponse.status}`);
  }
  const preflightHeaders = Object.fromEntries(preflightResponse.headers.entries());
  if (!preflightHeaders["access-control-allow-origin"]) {
    throw new Error("CORS preflight missing Access-Control-Allow-Origin header");
  }
  if (!preflightHeaders["access-control-allow-methods"]) {
    throw new Error("CORS preflight missing Access-Control-Allow-Methods header");
  }
  if (!preflightHeaders["access-control-allow-headers"]) {
    throw new Error("CORS preflight missing Access-Control-Allow-Headers header");
  }
  console.log("  OPTIONS preflight passed");

  console.log("CORS tests passed!");
}

async function testServerInfo() {
  console.log("Testing server info...");

  const transport = new StreamableHTTPClientTransport(new URL(BASE_URL));
  const client = new Client({ name: "integration-test", version: "1.0.0" }, { capabilities: {} });

  await client.connect(transport);

  const serverInfo = client.getServerVersion();
  if (!serverInfo) {
    throw new Error("Server info not available after connection");
  }
  if (serverInfo.name !== "commonware-library") {
    throw new Error(`Expected server name 'commonware-library', got '${serverInfo.name}'`);
  }
  if (!serverInfo.version || !/^\d+\.\d+\.\d+$/.test(serverInfo.version)) {
    throw new Error(`Invalid server version format: '${serverInfo.version}'`);
  }
  console.log(`Server info: ${serverInfo.name} v${serverInfo.version}`);

  await client.close();
  console.log("Server info test passed!");
}

async function testMcpTools() {
  console.log("Connecting to MCP server...");

  const transport = new StreamableHTTPClientTransport(new URL(BASE_URL));
  const client = new Client({ name: "integration-test", version: "1.0.0" }, { capabilities: {} });

  await client.connect(transport);
  console.log("Connected to MCP server");

  // Test list_versions
  console.log("\nTesting list_versions...");
  const versionsResult = await client.callTool({
    name: "list_versions",
    arguments: {},
  });
  console.log("list_versions result:", versionsResult.content[0].text.slice(0, 200) + "...");

  // Extract latest version from the result
  const versionMatch = versionsResult.content[0].text.match(/- (v[\d.]+) \(latest\)/);
  if (!versionMatch) {
    throw new Error("Could not find latest version in list_versions result");
  }
  const latestVersion = versionMatch[1];
  console.log("Latest version:", latestVersion);

  // Test search_code with substring mode (default, trigram requires 3+ characters)
  console.log("\nTesting search_code (substring mode)...");
  const substringResult = await client.callTool({
    name: "search_code",
    arguments: {
      query: "impl",
      mode: "substring",
      max_results: 3,
    },
  });
  if (substringResult.isError) {
    throw new Error(`search_code (substring) failed: ${substringResult.content[0].text}`);
  }
  if (substringResult.content[0].text.includes("No matches found")) {
    throw new Error("search_code (substring) returned no matches for 'impl'");
  }
  console.log(
    "search_code (substring) result:",
    substringResult.content[0].text.slice(0, 200) + "..."
  );

  // Test search_code with word mode
  console.log("\nTesting search_code (word mode)...");
  const wordResult = await client.callTool({
    name: "search_code",
    arguments: {
      query: "pub fn",
      mode: "word",
      max_results: 3,
    },
  });
  if (wordResult.isError) {
    throw new Error(`search_code (word) failed: ${wordResult.content[0].text}`);
  }
  if (wordResult.content[0].text.includes("No matches found")) {
    throw new Error("search_code (word) returned no matches for 'pub fn'");
  }
  console.log("search_code (word) result:", wordResult.content[0].text.slice(0, 200) + "...");

  // Test get_overview
  console.log("\nTesting get_overview...");
  const overviewResult = await client.callTool({
    name: "get_overview",
    arguments: {},
  });
  if (overviewResult.isError) {
    throw new Error(`get_overview failed: ${overviewResult.content[0].text}`);
  }
  console.log("get_overview result:", overviewResult.content[0].text.slice(0, 200) + "...");

  // Test list_crates
  console.log("\nTesting list_crates...");
  const cratesResult = await client.callTool({
    name: "list_crates",
    arguments: {},
  });
  if (cratesResult.isError) {
    throw new Error(`list_crates failed: ${cratesResult.content[0].text}`);
  }
  console.log("list_crates result:", cratesResult.content[0].text.slice(0, 200) + "...");

  // Test get_file with line numbers
  console.log("\nTesting get_file with line numbers...");
  const getFileResult = await client.callTool({
    name: "get_file",
    arguments: {
      path: "cryptography/src/lib.rs",
    },
  });
  if (getFileResult.isError) {
    throw new Error(`get_file failed: ${getFileResult.content[0].text}`);
  }
  // Verify output has line numbers (0-indexed)
  if (!getFileResult.content[0].text.includes("0: ")) {
    throw new Error("get_file output missing line numbers");
  }
  console.log("get_file result:", getFileResult.content[0].text.slice(0, 300) + "...");

  // Test get_file with line range
  console.log("\nTesting get_file with line range...");
  const getFileRangeResult = await client.callTool({
    name: "get_file",
    arguments: {
      path: "cryptography/src/lib.rs",
      start_line: 5,
      end_line: 10,
    },
  });
  if (getFileRangeResult.isError) {
    throw new Error(`get_file (range) failed: ${getFileRangeResult.content[0].text}`);
  }
  // Verify header shows line range
  if (!getFileRangeResult.content[0].text.includes("[lines 5-10]")) {
    throw new Error("get_file (range) output missing line range in header");
  }
  // Verify first line starts with 5:
  if (!getFileRangeResult.content[0].text.includes("\n5: ")) {
    throw new Error("get_file (range) output should start at line 5");
  }
  console.log("get_file (range) result:", getFileRangeResult.content[0].text.slice(0, 300) + "...");

  // Test line number alignment between search_code and get_file
  await testLineNumberAlignment(client);

  await client.close();
  console.log("\nAll MCP tool tests passed!");
}

async function testLineNumberAlignment(client) {
  console.log("\nTesting line number alignment between search_code and get_file...");

  // Search for a specific pattern that will have predictable results
  const searchResult = await client.callTool({
    name: "search_code",
    arguments: {
      query: "pub struct",
      mode: "substring",
      crate: "commonware-cryptography",
      max_results: 1,
    },
  });
  if (searchResult.isError) {
    throw new Error(`search_code failed: ${searchResult.content[0].text}`);
  }

  const searchText = searchResult.content[0].text;
  console.log("search_code snippet:", searchText.slice(0, 500));

  // Extract file path from search result (format: "## path/to/file.rs")
  const fileMatch = searchText.match(/## ([^\n]+\.rs)/);
  if (!fileMatch) {
    throw new Error("Could not extract file path from search_code result");
  }
  const filePath = fileMatch[1];
  console.log("Extracted file path:", filePath);

  // Extract a line number and its content from the snippet
  // Format: "N: line content" where N is 0-indexed
  const lineMatch = searchText.match(/(\d+): (.+)/);
  if (!lineMatch) {
    throw new Error("Could not extract line number from search_code snippet");
  }
  const lineNum = parseInt(lineMatch[1], 10);
  const expectedContent = lineMatch[2];
  console.log(`Extracted line ${lineNum}: "${expectedContent.slice(0, 50)}..."`);

  // Now fetch that exact line using get_file with start_line/end_line
  const getFileResult = await client.callTool({
    name: "get_file",
    arguments: {
      path: filePath,
      start_line: lineNum,
      end_line: lineNum,
    },
  });
  if (getFileResult.isError) {
    throw new Error(`get_file failed: ${getFileResult.content[0].text}`);
  }

  const getFileText = getFileResult.content[0].text;
  console.log("get_file result:", getFileText);

  // Extract the line content from get_file result
  const getFileLineMatch = getFileText.match(new RegExp(`${lineNum}: (.+)`));
  if (!getFileLineMatch) {
    throw new Error(`get_file output missing line ${lineNum}`);
  }
  const actualContent = getFileLineMatch[1];

  // Verify the content matches
  if (actualContent !== expectedContent) {
    throw new Error(
      `Line content mismatch!\n` +
        `  search_code line ${lineNum}: "${expectedContent}"\n` +
        `  get_file line ${lineNum}: "${actualContent}"`
    );
  }

  console.log("Line number alignment verified: search_code and get_file produce matching output!");
}

async function main() {
  try {
    // Test CORS support
    await testCors();

    // Test server info via MCP protocol
    await testServerInfo();

    // Trigger indexing (synchronous, waits for completion)
    await triggerIndexing();

    // Test MCP tools
    await testMcpTools();

    console.log("\n✓ All integration tests passed!");
    process.exit(0);
  } catch (error) {
    console.error("\n✗ Integration test failed:", error.message);
    process.exit(1);
  }
}

main();
