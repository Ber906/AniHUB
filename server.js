import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";
import { HiAnime, HiAnimeError } from "aniwatch";
import session from "express-session";
import fs from 'fs/promises';
import bcrypt from 'bcrypt';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const port = 5000;

// Storage functionality
const DATA_DIR = path.join(__dirname, 'data');
const DATABASE_FILE = path.join(DATA_DIR, 'database.json');

// Ensure data directory exists
async function ensureDataDir() {
    try {
        await fs.access(DATA_DIR);
    } catch {
        await fs.mkdir(DATA_DIR, { recursive: true });
    }
}

// Load database from JSON file
async function loadDatabase() {
    try {
        await ensureDataDir();
        const data = await fs.readFile(DATABASE_FILE, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        // If file doesn't exist or is empty, return default structure
        return {
            users: [],
            recently_played: {},
            favorites: {},
            watch_progress: {}
        };
    }
}

// Save database to JSON file
async function saveDatabase(database) {
    await ensureDataDir();
    await fs.writeFile(DATABASE_FILE, JSON.stringify(database, null, 2), 'utf-8');
}

// Generate unique ID
function generateId() {
    return Date.now().toString() + Math.random().toString(36).substr(2, 9);
}

// Hash password
async function hashPassword(password) {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
}

// Verify password
async function verifyPasswordHash(password, hash) {
    return await bcrypt.compare(password, hash);
}

const storage = {
    // Create a new user
    async createUser({ email, password, firstName, lastName }) {
        const database = await loadDatabase();
        
        // Check if user already exists
        const existingUser = database.users.find(user => user.email === email);
        if (existingUser) {
            throw new Error('User already exists');
        }
        
        // Hash password
        const hashedPassword = await hashPassword(password);
        
        // Create user object
        const user = {
            id: generateId(),
            email,
            password: hashedPassword,
            firstName,
            lastName,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        
        // Add user to array and save
        database.users.push(user);
        await saveDatabase(database);
        
        return user;
    },
    
    // Get user by email
    async getUserByEmail(email) {
        const database = await loadDatabase();
        return database.users.find(user => user.email === email);
    },
    
    // Get user by ID
    async getUser(id) {
        const database = await loadDatabase();
        return database.users.find(user => user.id === id);
    },
    
    // Verify user password and return user if valid
    async verifyPassword(email, password) {
        const user = await this.getUserByEmail(email);
        if (!user) {
            return null;
        }
        
        const isValid = await verifyPasswordHash(password, user.password);
        if (!isValid) {
            return null;
        }
        
        // Return user without password
        const { password: _, ...publicUser } = user;
        return publicUser;
    },
    
    // Update user
    async updateUser(id, updates) {
        const database = await loadDatabase();
        const userIndex = database.users.findIndex(user => user.id === id);
        
        if (userIndex === -1) {
            throw new Error('User not found');
        }
        
        // Update user with new data
        database.users[userIndex] = {
            ...database.users[userIndex],
            ...updates,
            updatedAt: new Date().toISOString()
        };
        
        await saveDatabase(database);
        return database.users[userIndex];
    },
    
    // Delete user
    async deleteUser(id) {
        const database = await loadDatabase();
        const userIndex = database.users.findIndex(user => user.id === id);
        
        if (userIndex === -1) {
            throw new Error('User not found');
        }
        
        database.users.splice(userIndex, 1);
        await saveDatabase(database);
        return true;
    },
    
    // Recently played storage functions
    async getRecentlyPlayed(userId) {
        try {
            const database = await loadDatabase();
            return database.recently_played[userId] || [];
        } catch (error) {
            // If database doesn't exist, return empty array
            return [];
        }
    },
    
    async addToRecentlyPlayed(userId, animeData) {
        try {
            const database = await loadDatabase();
            
            if (!database.recently_played[userId]) {
                database.recently_played[userId] = [];
            }
            
            // Remove existing entry if found
            database.recently_played[userId] = database.recently_played[userId].filter(item => 
                !(item.id === animeData.id && item.episode === animeData.episode)
            );
            
            // Add to beginning and limit to 10 items
            database.recently_played[userId].unshift({
                ...animeData,
                timestamp: Date.now()
            });
            database.recently_played[userId] = database.recently_played[userId].slice(0, 10);
            
            await saveDatabase(database);
            return database.recently_played[userId];
        } catch (error) {
            throw new Error('Failed to save recently played data');
        }
    },

    // Get user favorites
    async getFavorites(userId) {
        try {
            const database = await loadDatabase();
            return database.favorites[userId] || [];
        } catch (error) {
            // If database doesn't exist, return empty array
            return [];
        }
    },

    // Add anime to favorites
    async addToFavorites(userId, animeData) {
        try {
            const database = await loadDatabase();
            
            if (!database.favorites[userId]) {
                database.favorites[userId] = [];
            }
            
            // Check if already in favorites
            const exists = database.favorites[userId].find(item => item.id === animeData.id);
            if (exists) {
                throw new Error('Anime already in favorites');
            }
            
            // Add to favorites
            database.favorites[userId].unshift({
                ...animeData,
                addedAt: Date.now()
            });
            
            await saveDatabase(database);
            return database.favorites[userId];
        } catch (error) {
            throw new Error(error.message || 'Failed to add to favorites');
        }
    },

    // Remove anime from favorites
    async removeFromFavorites(userId, animeId) {
        try {
            const database = await loadDatabase();
            
            if (!database.favorites[userId]) {
                return [];
            }
            
            // Remove from favorites
            database.favorites[userId] = database.favorites[userId].filter(item => item.id !== animeId);
            
            await saveDatabase(database);
            return database.favorites[userId];
        } catch (error) {
            throw new Error('Failed to remove from favorites');
        }
    },
    
    // Watch progress tracking functions
    async getWatchProgress(userId, animeId, episode) {
        try {
            const database = await loadDatabase();
            const key = `${animeId}_${episode}`;
            return database.watch_progress[userId]?.[key] || { progress: 0, duration: 0, lastWatched: null };
        } catch (error) {
            return { progress: 0, duration: 0, lastWatched: null };
        }
    },
    
    async updateWatchProgress(userId, animeId, episode, progress, duration) {
        try {
            const database = await loadDatabase();
            
            if (!database.watch_progress[userId]) {
                database.watch_progress[userId] = {};
            }
            
            const key = `${animeId}_${episode}`;
            database.watch_progress[userId][key] = {
                progress: Math.floor(progress), // Store progress in seconds
                duration: Math.floor(duration), // Store duration in seconds
                lastWatched: Date.now()
            };
            
            await saveDatabase(database);
            return database.watch_progress[userId][key];
        } catch (error) {
            throw new Error('Failed to save watch progress');
        }
    }
};

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

// Session configuration - using memory store for JSON-based approach
app.use(session({
    secret: process.env.SESSION_SECRET || 'anime-streaming-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false, // Set to true in production with HTTPS
        maxAge: 7 * 24 * 60 * 60 * 1000 // 1 week
    }
}));

// Middleware
app.use(cors({
    credentials: true,
    origin: true
}));
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

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: true, message: 'Authentication required' });
    }
    next();
};

// Authentication routes
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { email, password, firstName, lastName } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: true, message: 'Email and password are required' });
        }
        
        // Check if user already exists
        const existingUser = await storage.getUserByEmail(email);
        if (existingUser) {
            return res.status(400).json({ error: true, message: 'User already exists' });
        }
        
        // Create new user
        const user = await storage.createUser({
            email,
            password,
            firstName,
            lastName
        });
        
        // Create session
        req.session.userId = user.id;
        
        // Return user without password
        const { password: _, ...publicUser } = user;
        res.json({ success: true, user: publicUser });
    } catch (error) {
        handleError(res, error, 'Failed to create user');
    }
});

app.post('/api/auth/signin', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: true, message: 'Email and password are required' });
        }
        
        // Verify user credentials
        const user = await storage.verifyPassword(email, password);
        if (!user) {
            return res.status(401).json({ error: true, message: 'Invalid email or password' });
        }
        
        // Create session
        req.session.userId = user.id;
        
        res.json({ success: true, user });
    } catch (error) {
        handleError(res, error, 'Failed to sign in');
    }
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return handleError(res, err, 'Failed to logout');
        }
        res.json({ success: true, message: 'Logged out successfully' });
    });
});

app.get('/api/auth/me', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: true, message: 'Not authenticated' });
        }
        
        const user = await storage.getUser(req.session.userId);
        if (!user) {
            return res.status(404).json({ error: true, message: 'User not found' });
        }
        
        // Return user without password
        const { password: _, ...publicUser } = user;
        res.json({ success: true, user: publicUser });
    } catch (error) {
        handleError(res, error, 'Failed to get user data');
    }
});

// Recently played endpoints
app.get('/api/recently-played', requireAuth, async (req, res) => {
    try {
        const recentlyPlayed = await storage.getRecentlyPlayed(req.session.userId);
        res.json({ success: true, data: recentlyPlayed });
    } catch (error) {
        handleError(res, error, 'Failed to fetch recently played');
    }
});

app.post('/api/recently-played', requireAuth, async (req, res) => {
    try {
        const { id, title, poster, episode, progress, duration } = req.body;
        
        if (!id || !title || !episode) {
            return res.status(400).json({ error: true, message: 'Missing required fields' });
        }
        
        const animeData = { 
            id, 
            title, 
            poster, 
            episode, 
            progress: progress || 0,
            duration: duration || 0
        };
        const updatedList = await storage.addToRecentlyPlayed(req.session.userId, animeData);
        
        res.json({ success: true, data: updatedList });
    } catch (error) {
        handleError(res, error, 'Failed to add to recently played');
    }
});

// Favorites endpoints
app.get('/api/favorites', requireAuth, async (req, res) => {
    try {
        const favorites = await storage.getFavorites(req.session.userId);
        res.json({ success: true, data: favorites });
    } catch (error) {
        handleError(res, error, 'Failed to fetch favorites');
    }
});

app.post('/api/favorites', requireAuth, async (req, res) => {
    try {
        const { id, title, poster, releaseDate, type } = req.body;
        
        if (!id || !title) {
            return res.status(400).json({ error: true, message: 'Missing required fields (id, title)' });
        }
        
        const animeData = { 
            id, 
            title, 
            poster: poster || '', 
            releaseDate: releaseDate || 'N/A',
            type: type || 'TV'
        };
        const updatedList = await storage.addToFavorites(req.session.userId, animeData);
        
        res.json({ success: true, data: updatedList });
    } catch (error) {
        if (error.message === 'Anime already in favorites') {
            return res.status(409).json({ error: true, message: error.message });
        }
        handleError(res, error, 'Failed to add to favorites');
    }
});

app.delete('/api/favorites/:animeId', requireAuth, async (req, res) => {
    try {
        const { animeId } = req.params;
        
        if (!animeId) {
            return res.status(400).json({ error: true, message: 'Anime ID is required' });
        }
        
        const updatedList = await storage.removeFromFavorites(req.session.userId, animeId);
        res.json({ success: true, data: updatedList });
    } catch (error) {
        handleError(res, error, 'Failed to remove from favorites');
    }
});

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
        
        const response = await Promise.race([
            fetch(url, {
                headers: {
                    'Referer': 'https://megacloud.blog/',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Accept': '*/*',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Connection': 'keep-alive'
                }
            }),
            new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Request timeout')), 8000)
            )
        ]);

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
            const buffer = await response.arrayBuffer();
            res.send(Buffer.from(buffer));
        }
        
    } catch (error) {
        // Only log errors for non-segment requests to reduce spam
        const { url } = req.query;
        if (url && !url.includes('seg-') && !url.includes('.ts')) {
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
