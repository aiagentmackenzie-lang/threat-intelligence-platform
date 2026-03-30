import { readFile } from "fs/promises";
import { z } from "zod";
import { logger } from "../utils/logger.js";

const FeedSchema = z.object({
  name: z.string().min(1),
  type: z.enum(["rest", "rss", "stix", "file"]),
  url: z.string().url(),
  auth: z
    .object({
      type: z.enum(["header", "query", "basic"]),
      headerName: z.string().optional(),
      env: z.string(),
    })
    .optional(),
  intervalMinutes: z.number().int().positive().default(60),
  enabled: z.boolean().default(false),
});

const ConfigSchema = z.array(FeedSchema);

export async function loadConfig(configPath = "./config/feeds.json") {
  try {
    const data = await readFile(configPath, "utf-8");
    const parsed = JSON.parse(data);
    const result = ConfigSchema.safeParse(parsed);

    if (!result.success) {
      logger.error({ errors: result.error.errors }, "Config validation failed");
      throw new Error(`Invalid config: ${result.error.errors.map((e) => e.message).join(", ")}`);
    }

    for (const feed of result.data) {
      if (feed.auth?.env) {
        const envValue = process.env[feed.auth.env];
        if (!envValue && feed.enabled) {
          logger.warn({ feed: feed.name, env: feed.auth.env }, "Auth env var not set for enabled feed");
        }
      }
    }

    logger.info({ feedCount: result.data.length }, "Configuration loaded successfully");
    return result.data;
  } catch (error) {
    logger.error({ error: error.message }, "Failed to load config");
    throw error;
  }
}
