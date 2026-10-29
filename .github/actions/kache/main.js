// Runs setup.sh. A failure leaves the job uncached rather than failing it.
const { spawnSync } = require("child_process");
const path = require("path");

const input = (name) => process.env[`INPUT_${name.toUpperCase()}`] || "";

const result = spawnSync("bash", [path.join(__dirname, "setup.sh")], {
  stdio: "inherit",
  env: {
    ...process.env,
    R2_BUCKET: input("r2-bucket"),
    R2_ENDPOINT: input("r2-endpoint"),
    R2_ACCESS_KEY_ID: input("r2-access-key-id"),
    R2_SECRET_ACCESS_KEY: input("r2-secret-access-key"),
    MANIFEST_KEY: input("manifest-key"),
  },
});
if (result.status !== 0) {
  console.log("::warning::kache setup failed, kache disabled for this job.");
}
