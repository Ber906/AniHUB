const express = require('express');
const cors = require('cors');
const path = require('path');
const { HiAnime, HiAnimeError } = require('aniwatch');

const app = express();
const port = 5000;

// Initialize the scraper
const hianime = new HiAnime.Scraper();

// Simple in-memory cache with TTL
const cache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

function setCache(key, data) {
    cache.set(key, { data, timestamp: Date.now() });
}

function getCache(key) {
    const cached = cache.get(key);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
        return cached.data;
    }
    cache.delete(key);
    return null;
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '.')));

// Error handler
const handleError = (res, error, message = 'An error occurred') => {
    console.error(message, error);
    res.status(500).json({ 
        error: true, 
        message: error instanceof HiAnimeError ? error.message : message 
    });
};

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Home page data
app.get('/api/home', async (req, res) => {
    try {
        const cacheKey = 'home';
        let data = getCache(cacheKey);
        
        if (!data) {
            data = await hianime.getHomePage();
            setCache(cacheKey, data);
        }
        
        res.json(data);
    } catch (error) {
        handleError(res, error, 'Failed to fetch home page data');
    }
});

// Anime search
app.get('/api/search', async (req, res) => {
    try {
        const { q: query, page = 1 } = req.query;
        if (!query) {
            return res.status(400).json({ error: true, message: 'Query parameter is required' });
        }
        
        const cacheKey = `search_${query}_${page}`;
        let data = getCache(cacheKey);
        
        if (!data) {
            data = await hianime.search(query, parseInt(page));
            setCache(cacheKey, data);
        }
        
        res.json(data);
    } catch (error) {
        handleError(res, error, 'Failed to search anime');
    }
});

// Search suggestions
app.get('/api/search/suggest', async (req, res) => {
    try {
        const { q: query } = req.query;
        if (!query) {
            return res.status(400).json({ error: true, message: 'Query parameter is required' });
        }
        const data = await hianime.searchSuggestions(query);
        res.json(data);
    } catch (error) {
        handleError(res, error, 'Failed to fetch search suggestions');
    }
});

// Anime info
app.get('/api/info', async (req, res) => {
    try {
        const { id: animeId } = req.query;
        if (!animeId) {
            return res.status(400).json({ error: true, message: 'ID parameter is required' });
        }
        
        const cacheKey = `info_${animeId}`;
        let data = getCache(cacheKey);
        
        if (!data) {
            data = await hianime.getInfo(animeId);
            setCache(cacheKey, data);
        }
        
        res.json(data);
    } catch (error) {
        handleError(res, error, 'Failed to fetch anime info');
    }
});

// Anime episodes
app.get('/api/episodes/:animeId', async (req, res) => {
    try {
        const { animeId } = req.params;
        
        const cacheKey = `episodes_${animeId}`;
        let data = getCache(cacheKey);
        
        if (!data) {
            data = await hianime.getEpisodes(animeId);
            setCache(cacheKey, data);
        }
        
        res.json(data);
    } catch (error) {
        handleError(res, error, 'Failed to fetch episodes');
    }
});

// Episode sources with parallel server attempts for faster loading
app.get('/api/episode-srcs', async (req, res) => {
    try {
        const { id: episodeId, server = 'hd-1', category = 'sub' } = req.query;
        if (!episodeId) {
            return res.status(400).json({ error: true, message: 'Episode ID parameter is required' });
        }

        // Cache key for faster subsequent requests
        const cacheKey = `episode_src_${episodeId}_${server}_${category}`;
        let cachedData = getCache(cacheKey);
        
        if (cachedData) {
            return res.json(cachedData);
        }

        // Try servers in parallel for faster loading - prioritize based on reliability
        const servers = ['hd-1', 'megacloud', 'hd-2'];
        const serverPromises = servers.map(async (serverName) => {
            try {
                console.log(`Trying server: ${serverName} for episode: ${episodeId}`);
                const result = await Promise.race([
                    hianime.getEpisodeSources(episodeId, serverName, category),
                    new Promise((_, reject) => setTimeout(() => reject(new Error('Server timeout')), 8000))
                ]);
                
                if (result && result.sources && result.sources.length > 0) {
                    console.log(`Success with server: ${serverName}`);
                    return { success: true, data: result, server: serverName };
                }
                return { success: false, server: serverName, error: 'No sources' };
            } catch (error) {
                console.log(`Server ${serverName} failed:`, error.message);
                return { success: false, server: serverName, error: error.message };
            }
        });

        // Wait for first successful response or all to fail
        const results = await Promise.allSettled(serverPromises);
        let episodeData = null;
        
        // Find first successful result
        for (const result of results) {
            if (result.status === 'fulfilled' && result.value.success) {
                episodeData = result.value.data;
                break;
            }
        }

        if (!episodeData) {
            throw new Error('No video sources available from any server');
        }

        // Cache successful result
        setCache(cacheKey, episodeData);
        res.json(episodeData);
    } catch (error) {
        handleError(res, error, 'Failed to fetch episode sources from all servers');
    }
});

// Proxy endpoint for video streaming
app.get('/api/proxy-video', async (req, res) => {
    try {
        const { url } = req.query;
        if (!url) {
            return res.status(400).json({ error: 'URL parameter required' });
        }

        // Reduce logging spam - only log master playlists and errors
        const isSegment = url.includes('seg-') || url.includes('.ts');
        if (!isSegment) {
            console.log('Proxying URL:', url);
        }
        const fetch = (await import('node-fetch')).default;
        
        const response = await fetch(url, {
            headers: {
                'Referer': 'https://megacloud.blog/',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Connection': 'keep-alive'
            },
            timeout: 10000 // 10 second timeout for faster fallback
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        // Set CORS headers with optimized caching
        res.set({
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
            'Access-Control-Allow-Headers': 'Range, Content-Range, Content-Length, Content-Type',
            'Content-Type': response.headers.get('content-type') || 'application/vnd.apple.mpegurl',
            'Cache-Control': url.includes('.m3u8') ? 'max-age=30' : 'max-age=300', // Cache segments longer
            'Access-Control-Max-Age': '86400'
        });

        // For m3u8 files, we need to modify the URLs to go through our proxy
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('mpegurl') || url.includes('.m3u8')) {
            const text = await response.text();
            // Only log for master playlist files, not individual segments
            if (!isSegment && !url.includes('index-f')) {
                console.log('Original m3u8 content:', text.substring(0, 200));
            }
            
            // Get the base URL from the original URL
            const baseUrl = url.substring(0, url.lastIndexOf('/') + 1);
            
            const modifiedContent = text.replace(
                /^(?!#)(.+)$/gm, // Match non-comment lines
                (match) => {
                    const line = match.trim();
                    if (line && !line.startsWith('#')) {
                        // Handle relative URLs
                        let fullUrl = line;
                        if (!line.startsWith('http')) {
                            fullUrl = baseUrl + line;
                        }
                        return `${req.protocol}://${req.get('host')}/api/proxy-video?url=${encodeURIComponent(fullUrl)}`;
                    }
                    return match;
                }
            );
            
            if (!isSegment && !url.includes('index-f')) {
                console.log('Modified m3u8 content:', modifiedContent.substring(0, 200));
            }
            res.send(modifiedContent);
        } else {
            // For other content, pipe directly
            const buffer = await response.buffer();
            res.send(buffer);
        }
        
    } catch (error) {
        // Only log errors for non-segment requests to reduce spam
        if (!url.includes('seg-') && !url.includes('.ts')) {
            console.error('Proxy error for', url.substring(url.lastIndexOf('/') + 1), ':', error.message);
        }
        res.status(500).json({ error: 'Failed to proxy video stream' });
    }
});

// Handle OPTIONS requests for CORS
app.options('/api/proxy-video', (req, res) => {
    res.set({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
        'Access-Control-Allow-Headers': 'Range, Content-Range, Content-Length, Content-Type'
    });
    res.status(200).end();
});

// Start server
app.listen(port, '0.0.0.0', () => {
    console.log(`AniStream server running on http://0.0.0.0:${port}`);
});