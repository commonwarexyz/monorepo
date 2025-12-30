#!/usr/bin/env node

/**
 * Integration test for the Commonware MCP server.
 *
 * This script:
 * 1. Triggers the scheduled handler to index versions
 * 2. Verifies the health endpoint
 * 3. Tests MCP tools via StreamableHTTP transport
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const BASE_URL = process.env.MCP_URL || "http://localhost:8787";

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function triggerIndexing() {
  console.log("Triggering scheduled indexing...");
  const response = await fetch(`${BASE_URL}/__scheduled?cron=*`);
  if (!response.ok) {
    throw new Error(`Failed to trigger indexing: ${response.status}`);
  }
  console.log("Indexing triggered successfully");
}

async function checkHealth() {
  console.log("Checking health endpoint...");
  const response = await fetch(`${BASE_URL}/health`);
  if (!response.ok) {
    throw new Error(`Health check failed: ${response.status}`);
  }
  const data = await response.json();
  console.log("Health check passed:", data);
  return data;
}

async function checkCORS() {
  console.log("Checking CORS headers...");

  // Test preflight request
  const preflightResponse = await fetch(`${BASE_URL}/health`, {
    method: "OPTIONS",
  });
  if (preflightResponse.status !== 204) {
    throw new Error(`CORS preflight failed: expected 204, got ${preflightResponse.status}`);
  }

  const allowOrigin = preflightResponse.headers.get("Access-Control-Allow-Origin");
  if (allowOrigin !== "*") {
    throw new Error(`CORS: expected Access-Control-Allow-Origin: *, got ${allowOrigin}`);
  }

  const allowMethods = preflightResponse.headers.get("Access-Control-Allow-Methods");
  if (!allowMethods || !allowMethods.includes("POST")) {
    throw new Error(`CORS: Access-Control-Allow-Methods missing POST: ${allowMethods}`);
  }

  const allowHeaders = preflightResponse.headers.get("Access-Control-Allow-Headers");
  if (!allowHeaders || !allowHeaders.includes("mcp-session-id")) {
    throw new Error(`CORS: Access-Control-Allow-Headers missing mcp-session-id: ${allowHeaders}`);
  }

  console.log("CORS preflight passed");

  // Test that actual response has CORS headers
  const response = await fetch(`${BASE_URL}/health`);
  const responseAllowOrigin = response.headers.get("Access-Control-Allow-Origin");
  if (responseAllowOrigin !== "*") {
    throw new Error(`CORS: health response missing Access-Control-Allow-Origin header`);
  }

  const exposeHeaders = response.headers.get("Access-Control-Expose-Headers");
  if (!exposeHeaders || !exposeHeaders.includes("mcp-session-id")) {
    throw new Error(`CORS: Access-Control-Expose-Headers missing mcp-session-id: ${exposeHeaders}`);
  }

  console.log("CORS headers check passed");
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

  await client.close();
  console.log("\nAll MCP tool tests passed!");
}

async function main() {
  try {
    // Check health first
    await checkHealth();

    // Check CORS headers
    await checkCORS();

    // Trigger indexing and wait for it to complete
    await triggerIndexing();

    // Wait a bit for indexing to complete (it fetches files from commonware.xyz)
    console.log("Waiting for indexing to complete...");
    await sleep(30000);

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
