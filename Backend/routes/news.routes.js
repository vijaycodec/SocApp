import express from "express";
import axios from "axios";
import https from "https";
import Parser from "rss-parser";
import redisClient from "../config/redisClient.js";

const router = express.Router();

// Cache configuration
const CACHE_TTL = 900; // 15 minutes in seconds
const NEWS_CACHE_KEY = 'cyber_news_feed';

// Axios instance with SSL verification disabled
const axiosInstance = axios.create({
  httpsAgent: new https.Agent({
    rejectUnauthorized: false,
  }),
});

// RSS Parser instance
const rssParser = new Parser({
  timeout: 5000,
  headers: {
    'User-Agent': 'SOC-Dashboard/1.0'
  }
});

/**
 * @route   GET /api/news/cyber
 * @desc    Fetch cybersecurity news from multiple sources
 * @access  Public
 */
router.get("/cyber", async (req, res) => {
  try {
    // Check Redis cache first
    try {
      const cachedData = await redisClient.get(NEWS_CACHE_KEY);
      if (cachedData) {
        console.log('✅ [CYBER NEWS] Cache HIT - Data fetched from Redis (15 min cache)');
        res.setHeader('X-Cache', 'HIT');
        return res.json(JSON.parse(cachedData));
      }
      console.log('❌ [CYBER NEWS] Cache MISS - Fetching from news sources...');
      res.setHeader('X-Cache', 'MISS');
    } catch (cacheError) {
      console.warn('⚠️ [CYBER NEWS] Redis cache check failed, continuing without cache');
    }

    const newsItems = [];

    // Fetch from Dev.to
    try {
      const devToResponse = await axiosInstance.get(
        "https://dev.to/api/articles?tag=cybersecurity&per_page=20",
        { timeout: 5000 }
      );

      if (devToResponse.status === 200 && Array.isArray(devToResponse.data)) {
        devToResponse.data.forEach((article) => {
          newsItems.push({
            title: article.title,
            description: article.description || article.title,
            url: article.url,
            published_at: article.published_at,
            source: "Dev.to",
            author: article.user?.name || "Unknown",
            tags: article.tag_list || [],
            reading_time: article.reading_time_minutes || 0,
          });
        });
      }
    } catch (err) {
      console.warn("[!] Failed to fetch from Dev.to:", err.message);
    }

    // Fetch from Dark Reading RSS
    try {
      const feed = await rssParser.parseURL("https://www.darkreading.com/rss.xml");

      feed.items.slice(0, 10).forEach((item) => {
        newsItems.push({
          title: item.title || "Untitled",
          description: item.contentSnippet?.substring(0, 200) || item.title || "",
          url: item.link || "",
          published_at: item.isoDate || item.pubDate || new Date().toISOString(),
          source: "Dark Reading",
          author: item.creator || "Dark Reading",
          tags: item.categories || ["security", "enterprise"],
          reading_time: 0,
        });
      });
    } catch (err) {
      console.warn("[!] Failed to fetch from Dark Reading:", err.message);
    }

    // Fetch from Reddit - netsec
    try {
      const netsecResponse = await axiosInstance.get(
        "https://www.reddit.com/r/netsec/hot.json?limit=15",
        {
          timeout: 5000,
          headers: { "User-Agent": "SOC-Dashboard/1.0" },
        }
      );

      if (
        netsecResponse.status === 200 &&
        netsecResponse.data?.data?.children
      ) {
        netsecResponse.data.data.children.forEach((post) => {
          const data = post.data;
          newsItems.push({
            title: data.title,
            description: data.selftext?.substring(0, 200) || data.title,
            url: `https://reddit.com${data.permalink}`,
            published_at: new Date(data.created_utc * 1000).toISOString(),
            source: "r/netsec",
            author: data.author,
            tags: ["reddit", "netsec"],
            comments: data.num_comments || 0,
            score: data.ups || 0,
          });
        });
      }
    } catch (err) {
      console.warn("[!] Failed to fetch from r/netsec:", err.message);
    }

    // Fetch from Threatpost RSS
    try {
      const feed = await rssParser.parseURL("https://threatpost.com/feed/");

      feed.items.slice(0, 10).forEach((item) => {
        newsItems.push({
          title: item.title || "Untitled",
          description: item.contentSnippet?.substring(0, 200) || item.title || "",
          url: item.link || "",
          published_at: item.isoDate || item.pubDate || new Date().toISOString(),
          source: "Threatpost",
          author: item.creator || "Threatpost",
          tags: item.categories || ["security", "threats"],
          reading_time: 0,
        });
      });
    } catch (err) {
      console.warn("[!] Failed to fetch from Threatpost:", err.message);
    }

    // Fetch from The Hacker News RSS
    try {
      const feed = await rssParser.parseURL("https://feeds.feedburner.com/TheHackersNews");

      feed.items.slice(0, 15).forEach((item) => {
        newsItems.push({
          title: item.title || "Untitled",
          description: item.contentSnippet?.substring(0, 200) || item.title || "",
          url: item.link || "",
          published_at: item.isoDate || item.pubDate || new Date().toISOString(),
          source: "The Hacker News",
          author: item.creator || "THN",
          tags: item.categories || ["security", "news"],
          reading_time: 0,
        });
      });
    } catch (err) {
      console.warn("[!] Failed to fetch from The Hacker News:", err.message);
    }

    // Fetch from Krebs on Security RSS
    try {
      const feed = await rssParser.parseURL("https://krebsonsecurity.com/feed/");

      feed.items.slice(0, 10).forEach((item) => {
        newsItems.push({
          title: item.title || "Untitled",
          description: item.contentSnippet?.substring(0, 200) || item.title || "",
          url: item.link || "",
          published_at: item.isoDate || item.pubDate || new Date().toISOString(),
          source: "Krebs on Security",
          author: item.creator || "Brian Krebs",
          tags: item.categories || ["security", "investigation"],
          reading_time: 0,
        });
      });
    } catch (err) {
      console.warn("[!] Failed to fetch from Krebs on Security:", err.message);
    }

    // Fetch from CISA Advisories RSS
    try {
      const feed = await rssParser.parseURL("https://www.cisa.gov/cybersecurity-advisories/all.xml");

      feed.items.slice(0, 10).forEach((item) => {
        newsItems.push({
          title: item.title || "Untitled",
          description: item.contentSnippet?.substring(0, 200) || item.title || "",
          url: item.link || "",
          published_at: item.isoDate || item.pubDate || new Date().toISOString(),
          source: "CISA",
          author: "CISA",
          tags: ["advisory", "government", "security"],
          reading_time: 0,
        });
      });
    } catch (err) {
      console.warn("[!] Failed to fetch from CISA:", err.message);
    }

    // Fetch from Schneier on Security RSS
    try {
      const feed = await rssParser.parseURL("https://www.schneier.com/feed/atom/");

      feed.items.slice(0, 10).forEach((item) => {
        newsItems.push({
          title: item.title || "Untitled",
          description: item.contentSnippet?.substring(0, 200) || item.title || "",
          url: item.link || "",
          published_at: item.isoDate || item.pubDate || new Date().toISOString(),
          source: "Schneier on Security",
          author: item.creator || "Bruce Schneier",
          tags: item.categories || ["security", "expert-opinion"],
          reading_time: 0,
        });
      });
    } catch (err) {
      console.warn("[!] Failed to fetch from Schneier on Security:", err.message);
    }

    // Fetch from SecurityWeek RSS
    try {
      const feed = await rssParser.parseURL("https://www.securityweek.com/feed/");

      feed.items.slice(0, 10).forEach((item) => {
        newsItems.push({
          title: item.title || "Untitled",
          description: item.contentSnippet?.substring(0, 200) || item.title || "",
          url: item.link || "",
          published_at: item.isoDate || item.pubDate || new Date().toISOString(),
          source: "SecurityWeek",
          author: item.creator || "SecurityWeek",
          tags: item.categories || ["security", "enterprise"],
          reading_time: 0,
        });
      });
    } catch (err) {
      console.warn("[!] Failed to fetch from SecurityWeek:", err.message);
    }

    // Balance distribution: Take top N from each source, then sort by date
    const balancedNews = [];
    const sourceGroups = {};

    // Group news by source
    newsItems.forEach(item => {
      if (!sourceGroups[item.source]) {
        sourceGroups[item.source] = [];
      }
      sourceGroups[item.source].push(item);
    });

    // Sort each source group by date and take top 3-4 items per source
    const itemsPerSource = {
      'Dev.to': 3,
      'Dark Reading': 3,
      'r/netsec': 3,
      'Threatpost': 3,
      'The Hacker News': 4,
      'Krebs on Security': 3,
      'CISA': 4,
      'Schneier on Security': 3,
      'SecurityWeek': 4
    };

    Object.keys(sourceGroups).forEach(source => {
      const sorted = sourceGroups[source].sort(
        (a, b) => new Date(b.published_at) - new Date(a.published_at)
      );
      const limit = itemsPerSource[source] || 3;
      balancedNews.push(...sorted.slice(0, limit));
    });

    // Final sort by date (newest first)
    balancedNews.sort(
      (a, b) => new Date(b.published_at) - new Date(a.published_at)
    );

    const responseData = {
      total: balancedNews.length,
      news: balancedNews,
      last_updated: new Date().toISOString(),
    };

    // Set Redis cache
    try {
      await redisClient.set(NEWS_CACHE_KEY, JSON.stringify(responseData), {
        EX: CACHE_TTL,
        NX: true
      });
      console.log('💾 [CYBER NEWS] Data cached in Redis for 15 minutes');
      console.log('   Total news items cached:', balancedNews.length);
    } catch (cacheError) {
      console.warn('⚠️ [CYBER NEWS] Redis cache set failed, continuing without cache');
    }

    res.json(responseData);
  } catch (error) {
    console.error("Error fetching cyber news:", error.message);
    res.status(500).json({
      error: "Failed to fetch cybersecurity news",
      total: 0,
      news: [],
    });
  }
});

export default router;
