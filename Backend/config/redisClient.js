import redis from "redis";
import dotenv from "dotenv";

dotenv.config();

const redisClient = redis.createClient({
  url: process.env.REDIS_URL || "redis://redis:6379", // use service name, not localhost redis://127.0.0.1:6379
  socket: {
    reconnectStrategy: (retries) => {
      if (retries > 5) {
        console.log("Too many retries on REDIS. Connection Terminated");
        return new Error("Too many retries.");
      }
      return retries * 500; // exponential backoff
    },
  },
});

redisClient.on("error", (err) => console.error("Redis Client Error:", err));
redisClient.on("connect", () => console.log("Redis Client Connected"));
redisClient.on("ready", () => console.log("Redis Client Ready"));
redisClient.on("reconnecting", () => console.log("Redis Client Reconnecting"));

(async () => {
  await redisClient.connect();
})();

export default redisClient;
