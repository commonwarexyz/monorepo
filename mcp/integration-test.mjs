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

  // Test search_code (trigram requires 3+ characters)
  console.log("\nTesting search_code...");
  const searchResult = await client.callTool({
    name: "search_code",
    arguments: {
      query: "impl",
      max_results: 3,
    },
  });
  if (searchResult.isError) {
    throw new Error(`search_code failed: ${searchResult.content[0].text}`);
  }
  if (searchResult.content[0].text.includes("No matches found")) {
    throw new Error("search_code returned no matches for 'impl'");
  }
  console.log("search_code result:", searchResult.content[0].text.slice(0, 200) + "...");

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
