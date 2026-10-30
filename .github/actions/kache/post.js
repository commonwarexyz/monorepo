// Runs post.sh when the job ends, if setup.sh started kache.
const { spawnSync } = require("child_process");
const path = require("path");

if (process.env.STATE_enabled === "true") {
  const input = (name) => process.env[`INPUT_${name.toUpperCase()}`] || "";
  const result = spawnSync("bash", [path.join(__dirname, "post.sh")], {
    stdio: "inherit",
    env: {
      ...process.env,
      KACHE_S3_ACCESS_KEY: input("r2-access-key-id"),
      KACHE_S3_SECRET_KEY: input("r2-secret-access-key"),
    },
  });
  if (result.status !== 0) {
    console.log("::warning::kache shutdown failed.");
  }
}
