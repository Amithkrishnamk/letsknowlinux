const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Body Parsers & Cookie Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser('lkl-secured-cookie-key'));

// Express Session configuration with Signed Cookie
app.use(session({
  name: 'lkl.session',
  secret: 'lkl-secured-cookie-key',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false, // set to true if running over https
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Serve static assets from public folder
app.use(express.static(path.join(__dirname, 'public')));

// --- GAME CONFIG & VIRTUAL FILESYSTEM ---
const FLAGS = {
  1: "LKL{t3rm1n4l_0r13nt4t10n_pwn3d}",
  2: "LKL{ls_h1dd3n_4v41l4bl3}",
  3: "LKL{grep_3ff1c13nt_f1lt3r1ng}"
};

const BRIEFING_TEXT = `
================================================================================
LETS KNOW LINUX SECURITY AUDIT - LEVEL 1
================================================================================
Welcome, Trainee.

An intrusion has been detected in Sector 7. A hacker managed to read raw configs,
leaving a trace flag in this directory. 
Your objective is to find the flag in this directory and submit it to advance.

INSTRUCTIONS:
1. Run 'pwd' to verify your workspace path.
2. Run 'ls' to see the files.
3. Run 'cat briefing.txt' to view the content.

LEVEL 1 TARGET FLAG:
${FLAGS[1]}

Copy the flag above and paste it into the "Submit Flag" dashboard card to progress.
================================================================================
`;

const HIDDEN_FLAG_TEXT = `
================================================================================
LETS KNOW LINUX SECURITY AUDIT - LEVEL 2
================================================================================
Status: DECRYPTED

Well done on submitting the Level 1 flag.
The intruder exfiltrated security credentials and hid them in this folder.
A standard directory list ('ls') will not reveal hidden items.
In Unix shells, files prefixed with a period '.' are hidden.

INSTRUCTIONS:
1. Run 'ls -a' to view all files, including hidden files.
2. Run 'cat .hidden_flag' to reveal the Level 2 flag.

LEVEL 2 TARGET FLAG:
${FLAGS[2]}
================================================================================
`;

// Helper to generate access logs
const generateAccessLogs = () => {
  const ips = ['192.168.1.34', '10.0.0.12', '172.16.254.1', '192.168.1.102', '185.190.140.23', '8.8.8.8', '192.168.1.1'];
  const endpoints = ['/index.html', '/login.php', '/api/users', '/static/css/theme.css', '/js/dashboard.js', '/wp-admin/index.php', '/config.json', '/api/v1/auth/login', '/img/hero.png'];
  const userAgents = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'Curl/7.68.0', 'Python-urllib/3.9', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 'Wget/1.20.3 (linux-gnu)'];
  const logs = [];
  
  for (let i = 0; i < 118; i++) {
    const ip = ips[Math.floor(Math.random() * ips.length)];
    const endpoint = endpoints[Math.floor(Math.random() * endpoints.length)];
    const ua = userAgents[Math.floor(Math.random() * userAgents.length)];
    const status = Math.random() > 0.85 ? '404' : (Math.random() > 0.9 ? '403' : '200');
    const bytes = Math.floor(Math.random() * 8000) + 90;
    const minute = String(Math.floor(i / 6)).padStart(2, '0');
    const second = String(Math.floor(Math.random() * 60)).padStart(2, '0');
    const time = `2026-05-20 18:${minute}:${second}`;
    logs.push(`${time} [INFO] IP: ${ip} - GET ${endpoint} - STATUS: ${status} - SIZE: ${bytes}B - UA: "${ua}"`);
  }
  
  // Inject Level 3 flag in a random position in access.log
  const flagIndex = Math.floor(Math.random() * 40) + 40;
  logs.splice(flagIndex, 0, `2026-05-20 18:24:11 [SYSTEM] SUCCESS - ADMIN_TOKEN: ${FLAGS[3]}`);
  return logs.join('\n');
};

const ACCESS_LOG_TEXT = generateAccessLogs();

// Command Split/Parse that respects quotes
function parseCommandArgs(inputStr) {
  const args = [];
  let current = '';
  let inQuotes = false;
  let quoteChar = null;

  for (let i = 0; i < inputStr.length; i++) {
    const char = inputStr[i];
    if ((char === '"' || char === "'") && (i === 0 || inputStr[i - 1] !== '\\')) {
      if (inQuotes && char === quoteChar) {
        inQuotes = false;
        quoteChar = null;
      } else if (!inQuotes) {
        inQuotes = true;
        quoteChar = char;
      } else {
        current += char;
      }
    } else if (char === ' ' && !inQuotes) {
      if (current) {
        args.push(current);
        current = '';
      }
    } else {
      current += char;
    }
  }
  if (current) {
    args.push(current);
  }
  return args;
}

// --- VIRTUAL FILESYSTEM SUPPORT ---

function initVFS(level = 1) {
  const vfs = {
    "/": { type: "dir", mode: "rwxr-xr-x", owner: "root", group: "root" },
    "/home": { type: "dir", mode: "rwxr-xr-x", owner: "root", group: "root" },
    "/home/user": { type: "dir", mode: "rwxr-xr-x", owner: "user", group: "user" },
    "/home/user/briefing.txt": { 
      type: "file", 
      content: BRIEFING_TEXT, 
      mode: "rw-r--r--", 
      owner: "user", 
      group: "user" 
    },
    "/var": { type: "dir", mode: "rwxr-xr-x", owner: "root", group: "root" },
    "/var/log": { type: "dir", mode: "rwxr-xr-x", owner: "root", group: "root" },
    "/etc": { type: "dir", mode: "rwxr-xr-x", owner: "root", group: "root" },
    "/tmp": { type: "dir", mode: "rwxrwxrwt", owner: "root", group: "root" }
  };
  
  if (level >= 2) {
    vfs["/home/user/.hidden_flag"] = {
      type: "file",
      content: HIDDEN_FLAG_TEXT,
      mode: "rw-r-----",
      owner: "user",
      group: "user"
    };
  }
  if (level >= 3) {
    vfs["/home/user/access.log"] = {
      type: "file",
      content: ACCESS_LOG_TEXT,
      mode: "rw-r--r--",
      owner: "user",
      group: "user"
    };
  }
  return vfs;
}

function resolvePath(cwd, targetPath) {
  if (!targetPath) return cwd;
  
  let absolute = targetPath.startsWith('/') 
    ? targetPath 
    : path.posix.join(cwd, targetPath);
    
  if (targetPath === '~' || targetPath.startsWith('~/')) {
    absolute = targetPath.replace('~', '/home/user');
  }
  
  const segments = absolute.split('/').filter(Boolean);
  const resolvedSegments = [];
  for (const seg of segments) {
    if (seg === '.') {
      continue;
    } else if (seg === '..') {
      resolvedSegments.pop();
    } else {
      resolvedSegments.push(seg);
    }
  }
  return '/' + resolvedSegments.join('/');
}

// Initializing Game Session State Middleware
app.use((req, res, next) => {
  if (!req.session.gameState) {
    req.session.gameState = {
      level: 1,
      completedFlags: [],
      cwd: "/home/user",
      vfs: null,
      editor: null,
      pager: null
    };
  }
  if (!req.session.gameState.vfs) {
    req.session.gameState.vfs = initVFS(req.session.gameState.level);
  }
  next();
});

// --- API ENDPOINTS ---

// Get active game state with current directory files
app.get('/api/state', (req, res) => {
  const vfs = req.session.gameState.vfs || {};
  const userFiles = [];
  
  Object.keys(vfs).forEach(p => {
    const parent = p.substring(0, p.lastIndexOf('/')) || '/';
    const name = p.substring(p.lastIndexOf('/') + 1);
    
    if (parent === '/home/user') {
      userFiles.push({
        name,
        type: vfs[p].type,
        hidden: name.startsWith('.')
      });
    }
  });

  res.json({
    level: req.session.gameState.level,
    completedFlags: req.session.gameState.completedFlags,
    cwd: req.session.gameState.cwd || "/home/user",
    files: userFiles
  });
});

// Submit Level Flag
app.post('/api/submit-flag', (req, res) => {
  const { flag } = req.body;
  if (!flag) {
    return res.status(400).json({ success: false, message: "Flag string cannot be empty." });
  }

  const currentLevel = req.session.gameState.level;
  const expectedFlag = FLAGS[currentLevel];

  if (flag.trim() === expectedFlag) {
    req.session.gameState.completedFlags.push(expectedFlag);
    
    let nextLevel = currentLevel;
    let gameCompleted = false;

    if (currentLevel < 3) {
      nextLevel = currentLevel + 1;
      req.session.gameState.level = nextLevel;
      
      // Inject Level-Up files into in-memory VFS
      if (nextLevel === 2) {
        req.session.gameState.vfs["/home/user/.hidden_flag"] = {
          type: "file",
          content: HIDDEN_FLAG_TEXT,
          mode: "rw-r-----",
          owner: "user",
          group: "user"
        };
      } else if (nextLevel === 3) {
        req.session.gameState.vfs["/home/user/access.log"] = {
          type: "file",
          content: ACCESS_LOG_TEXT,
          mode: "rw-r--r--",
          owner: "user",
          group: "user"
        };
      }
    } else {
      gameCompleted = true;
    }

    // Save session manually to be safe
    req.session.save((err) => {
      if (err) {
        return res.status(500).json({ success: false, message: "Session saving error." });
      }
      return res.json({
        success: true,
        level: nextLevel,
        gameCompleted,
        message: gameCompleted 
          ? "FLAG ACCEPTED. Congratulations! You've restored the entire mainframe system!" 
          : `FLAG ACCEPTED. Welcome to Level ${nextLevel}!`
      });
    });
  } else {
    return res.status(400).json({ 
      success: false, 
      message: "[-] INVALID FLAG SUBMISSION. Check formatting or spelling." 
    });
  }
});

// Command Execution Endpoint
app.post('/api/terminal', (req, res) => {
  const { command } = req.body;
  if (command === undefined) {
    return res.status(400).json({ error: "Missing command parameter." });
  }

  // --- EDITOR MOCK REDIRECTS ---
  if (req.session.gameState.editor) {
    const editor = req.session.gameState.editor;
    const isVim = editor.type === 'vim';

    if (isVim) {
      if (command.trim() === ':wq') {
        req.session.gameState.vfs[editor.file] = {
          type: "file",
          content: editor.content,
          mode: "rw-r--r--",
          owner: "user",
          group: "user"
        };
        req.session.gameState.editor = null;
        return res.json({ output: `[VIM: "${editor.file.split('/').pop()}" saved and closed.]` });
      } else if (command.trim() === ':q') {
        req.session.gameState.editor = null;
        return res.json({ output: `[VIM: closed without saving changes.]` });
      } else {
        editor.content += command + "\n";
        return res.json({ output: `~ \n~ \n[VIM: buffer updated. Type ':wq' to write/quit, or ':q' to abort]` });
      }
    } else {
      if (command.trim() === 'exit') {
        req.session.gameState.vfs[editor.file] = {
          type: "file",
          content: editor.content,
          mode: "rw-r--r--",
          owner: "user",
          group: "user"
        };
        req.session.gameState.editor = null;
        return res.json({ output: `[NANO: "${editor.file.split('/').pop()}" saved and closed.]` });
      } else {
        editor.content += command + "\n";
        return res.json({ output: `[NANO: line added. Total lines: ${editor.content.split('\n').length - 1}. Type 'exit' to save and close.]` });
      }
    }
  }

  // --- PAGER LESS REDIRECTS ---
  if (req.session.gameState.pager) {
    const pager = req.session.gameState.pager;
    if (command.trim().toLowerCase() === 'q' || command.trim().toLowerCase() === 'exit') {
      req.session.gameState.pager = null;
      return res.json({ output: `[Exited pager]` });
    }
    
    const lines = pager.content.split('\n');
    const start = pager.offset;
    const end = Math.min(start + 10, lines.length);
    const chunk = lines.slice(start, end).join('\n');
    
    if (end >= lines.length) {
      req.session.gameState.pager = null;
      return res.json({ output: chunk + `\n<span class="text-amber-500">[END OF FILE - pager closed]</span>` });
    }
    
    pager.offset = end;
    return res.json({ 
      output: chunk + `\n<span class="text-amber-500">-- less: lines ${start + 1}-${end} of ${lines.length} (press ENTER to scroll, or 'q' to quit) --</span>` 
    });
  }

  const sanitized = command.trim();
  if (!sanitized) {
    return res.json({ output: "" });
  }

  let tokens = parseCommandArgs(sanitized);
  let isSudo = false;
  if (tokens[0] === 'sudo') {
    isSudo = true;
    tokens = tokens.slice(1);
  }

  if (tokens.length === 0) {
    return res.json({ output: "" });
  }

  const cmd = tokens[0].toLowerCase();
  const args = tokens.slice(1);
  const cwd = req.session.gameState.cwd || "/home/user";
  const vfs = req.session.gameState.vfs;

  let output = "";
  let isError = false;

  switch (cmd) {
    case 'pwd':
      output = cwd;
      break;

    case 'whoami':
      output = isSudo ? "root" : "user";
      break;

    case 'uname':
      if (args.includes('-a') || args.includes('-s') || args.length === 0) {
        output = "Linux letsknowlinux 5.4.0-77-generic #86-Ubuntu SMP Wed May 20 18:24:11 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux";
      } else {
        output = "Linux";
      }
      break;

    case 'df':
      output = `Filesystem      Size  Used Avail Use% Mounted on\r
/dev/sda1        40G   12G   28G  30% /\r
tmpfs           1.9G     0  1.9G   0% /dev/shm\r
/dev/loop0       55M   55M     0 100% /snap/core`;
      break;

    case 'cd': {
      const target = args[0] || '~';
      const resolved = resolvePath(cwd, target);
      const item = vfs[resolved];
      
      if (!item) {
        output = `cd: ${target}: No such file or directory`;
        isError = true;
        break;
      }
      if (item.type !== 'dir') {
        output = `cd: ${target}: Not a directory`;
        isError = true;
        break;
      }
      
      req.session.gameState.cwd = resolved;
      break;
    }

    case 'ls': {
      const showHidden = args.some(arg => arg.startsWith('-') && arg.includes('a'));
      const longFormat = args.some(arg => arg.startsWith('-') && arg.includes('l'));
      
      const itemsInDir = [];
      Object.keys(vfs).forEach(p => {
        if (p === cwd) return;
        const parent = p.substring(0, p.lastIndexOf('/')) || '/';
        const name = p.substring(p.lastIndexOf('/') + 1);
        
        if (parent === cwd) {
          itemsInDir.push({ path: p, name, ...vfs[p] });
        }
      });

      if (showHidden) {
        itemsInDir.unshift({ name: '..', type: 'dir', mode: 'rwxr-xr-x', owner: 'root', group: 'root', content: '' });
        itemsInDir.unshift({ name: '.', type: 'dir', mode: 'rwxr-xr-x', owner: 'root', group: 'root', content: '' });
      } else {
        const visible = itemsInDir.filter(i => !i.name.startsWith('.'));
        itemsInDir.length = 0;
        itemsInDir.push(...visible);
      }

      if (longFormat) {
        output = itemsInDir.map(item => {
          const prefix = item.type === 'dir' ? 'd' : '-';
          const size = item.type === 'dir' ? 4096 : (item.content || '').length;
          const dateStr = "May 20 18:00";
          return `${prefix}${item.mode}  1 ${item.owner} ${item.group}  ${size} ${dateStr} ${item.name}`;
        }).join('\n');
      } else {
        output = itemsInDir.map(item => {
          if (item.type === 'dir') {
            return `<span class="text-cyan-500 font-bold hover:underline cursor-pointer" onclick="autofillCommand('cd ${item.name}; ls')">${item.name}</span>`;
          } else if (item.name.endsWith('.log')) {
            return `<span class="text-amber-400 font-bold hover:underline cursor-pointer" onclick="autofillCommand('cat ${item.name}')">${item.name}</span>`;
          }
          return `<span class="text-emerald-400 font-bold hover:underline cursor-pointer" onclick="autofillCommand('cat ${item.name}')">${item.name}</span>`;
        }).join('&nbsp;&nbsp;&nbsp;&nbsp;');
      }
      break;
    }

    case 'mkdir': {
      if (args.length === 0) {
        output = "mkdir: missing operand";
        isError = true;
        break;
      }
      const target = args[0];
      const resolved = resolvePath(cwd, target);
      if (vfs[resolved]) {
        output = `mkdir: cannot create directory ‘${target}’: File exists`;
        isError = true;
        break;
      }
      
      const parentPath = resolved.substring(0, resolved.lastIndexOf('/')) || '/';
      if (!vfs[parentPath] || vfs[parentPath].type !== 'dir') {
        output = `mkdir: cannot create directory ‘${target}’: No such file or directory`;
        isError = true;
        break;
      }
      
      vfs[resolved] = {
        type: "dir",
        mode: "rwxr-xr-x",
        owner: isSudo ? "root" : "user",
        group: isSudo ? "root" : "user"
      };
      break;
    }

    case 'touch': {
      if (args.length === 0) {
        output = "touch: missing file operand";
        isError = true;
        break;
      }
      const target = args[0];
      const resolved = resolvePath(cwd, target);
      
      const parentPath = resolved.substring(0, resolved.lastIndexOf('/')) || '/';
      if (!vfs[parentPath] || vfs[parentPath].type !== 'dir') {
        output = `touch: cannot touch ‘${target}’: No such file or directory`;
        isError = true;
        break;
      }

      if (!vfs[resolved]) {
        vfs[resolved] = {
          type: "file",
          content: "",
          mode: "rw-r--r--",
          owner: isSudo ? "root" : "user",
          group: isSudo ? "user" : "user"
        };
      }
      break;
    }

    case 'cp': {
      if (args.length < 2) {
        output = "cp: missing destination file operand";
        isError = true;
        break;
      }
      const src = args[0];
      const dest = args[1];
      
      const srcResolved = resolvePath(cwd, src);
      const srcItem = vfs[srcResolved];
      if (!srcItem) {
        output = `cp: cannot stat ‘${src}’: No such file or directory`;
        isError = true;
        break;
      }
      if (srcItem.type === 'dir') {
        output = `cp: -r not specified; omitting directory ‘${src}’`;
        isError = true;
        break;
      }
      
      let destResolved = resolvePath(cwd, dest);
      const destItem = vfs[destResolved];
      if (destItem && destItem.type === 'dir') {
        const filename = srcResolved.split('/').pop();
        destResolved = path.posix.join(destResolved, filename);
      }
      
      vfs[destResolved] = {
        type: "file",
        content: srcItem.content,
        mode: srcItem.mode,
        owner: isSudo ? "root" : "user",
        group: isSudo ? "user" : "user"
      };
      break;
    }

    case 'mv': {
      if (args.length < 2) {
        output = "mv: missing destination file operand";
        isError = true;
        break;
      }
      const src = args[0];
      const dest = args[1];
      
      const srcResolved = resolvePath(cwd, src);
      const srcItem = vfs[srcResolved];
      if (!srcItem) {
        output = `mv: cannot stat ‘${src}’: No such file or directory`;
        isError = true;
        break;
      }
      
      let destResolved = resolvePath(cwd, dest);
      const destItem = vfs[destResolved];
      if (destItem && destItem.type === 'dir') {
        const filename = srcResolved.split('/').pop();
        destResolved = path.posix.join(destResolved, filename);
      }
      
      if (srcItem.type === 'dir') {
        Object.keys(vfs).forEach(p => {
          if (p.startsWith(srcResolved + '/')) {
            const relative = p.substring(srcResolved.length);
            const newPath = destResolved + relative;
            vfs[newPath] = vfs[p];
            delete vfs[p];
          }
        });
      }
      
      vfs[destResolved] = srcItem;
      delete vfs[srcResolved];
      break;
    }

    case 'rm': {
      if (args.length === 0) {
        output = "rm: missing operand";
        isError = true;
        break;
      }
      
      const isRecursive = args.includes('-r') || args.includes('-rf') || args.includes('-f') && args.includes('-r');
      const cleanArgs = args.filter(a => !a.startsWith('-'));
      if (cleanArgs.length === 0) {
        output = "rm: missing file operand";
        isError = true;
        break;
      }
      
      const target = cleanArgs[0];
      const resolved = resolvePath(cwd, target);
      const item = vfs[resolved];
      if (!item) {
        output = `rm: cannot remove ‘${target}’: No such file or directory`;
        isError = true;
        break;
      }
      
      if (item.type === 'dir' && !isRecursive) {
        output = `rm: cannot remove ‘${target}’: Is a directory`;
        isError = true;
        break;
      }
      
      delete vfs[resolved];
      Object.keys(vfs).forEach(p => {
        if (p.startsWith(resolved + '/')) {
          delete vfs[p];
        }
      });
      break;
    }

    case 'chmod': {
      if (args.length < 2) {
        output = "chmod: missing operand";
        isError = true;
        break;
      }
      const mode = args[0];
      const target = args[1];
      const resolved = resolvePath(cwd, target);
      if (!vfs[resolved]) {
        output = `chmod: cannot access ‘${target}’: No such file or directory`;
        isError = true;
        break;
      }
      
      let cleanMode = vfs[resolved].mode;
      if (mode === '+x') {
        cleanMode = "rwxr-xr-x";
      } else if (/^[0-7]{3}$/.test(mode)) {
        const mapping = {
          '7': 'rwx', '6': 'rw-', '5': 'r-x', '4': 'r--', '3': '-wx', '2': '-w-', '1': '--x', '0': '---'
        };
        cleanMode = mode.split('').map(digit => mapping[digit]).join('');
      }
      
      vfs[resolved].mode = cleanMode;
      break;
    }

    case 'chown': {
      if (args.length < 2) {
        output = "chown: missing operand";
        isError = true;
        break;
      }
      const ownerGroup = args[0];
      const target = args[1];
      const resolved = resolvePath(cwd, target);
      if (!vfs[resolved]) {
        output = `chown: cannot access ‘${target}’: No such file or directory`;
        isError = true;
        break;
      }
      
      const parts = ownerGroup.split(':');
      const owner = parts[0] || vfs[resolved].owner;
      const group = parts[1] || owner || vfs[resolved].group;
      
      vfs[resolved].owner = owner;
      vfs[resolved].group = group;
      break;
    }

    case 'cat': {
      if (args.length === 0) {
        output = "cat: missing file operand. Usage: cat [filename]";
        isError = true;
        break;
      }
      const target = args[0];
      const resolved = resolvePath(cwd, target);
      const item = vfs[resolved];
      if (!item) {
        output = `cat: ${target}: No such file or directory`;
        isError = true;
        break;
      }
      if (item.type === 'dir') {
        output = `cat: ${target}: Is a directory`;
        isError = true;
        break;
      }
      
      if (resolved.endsWith('access.log')) {
        const lineCount = item.content.split('\n').length;
        output = `<div class="text-slate-500 border-l border-amber-500/20 pl-2 text-xs h-64 overflow-y-auto font-mono scroll-smooth mb-2">${item.content}</div>
<span class="text-amber-500 font-bold">[SYSTEM WARNING] Buffer overflow risk avoided!</span>\r
Printed ${lineCount} log lines. Searching manually is inefficient.\r
Use '<span class="text-yellow-400 font-bold">grep</span>' to filter specific records.\r
Example: <span class="text-yellow-400">grep "FLAG" access.log</span>`;
      } else {
        output = item.content;
      }
      break;
    }

    case 'grep': {
      if (args.length === 0) {
        output = "grep: missing search pattern. Usage: grep [pattern] [filename]";
        isError = true;
        break;
      }
      if (args.length === 1) {
        output = "grep: missing file operand. Usage: grep [pattern] [filename]";
        isError = true;
        break;
      }
      
      let isCaseInsensitive = false;
      const cleanArgs = args.filter(a => {
        if (a === '-i' || a === '--ignore-case') {
          isCaseInsensitive = true;
          return false;
        }
        return true;
      });

      if (cleanArgs.length < 2) {
        output = "grep: missing parameters. Usage: grep [pattern] [filename]";
        isError = true;
        break;
      }

      const pattern = cleanArgs[0];
      const filename = cleanArgs[1];
      const resolved = resolvePath(cwd, filename);
      const item = vfs[resolved];
      
      if (!item) {
        output = `grep: ${filename}: No such file or directory`;
        isError = true;
        break;
      }
      if (item.type === 'dir') {
        output = `grep: ${filename}: Is a directory`;
        isError = true;
        break;
      }
      
      const lines = item.content.split('\n');
      const escapeRegExp = (s) => s.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
      const regex = new RegExp(escapeRegExp(pattern), isCaseInsensitive ? 'i' : '');
      
      const matched = lines.filter(l => regex.test(l));
      if (matched.length > 0) {
        output = matched.map(l => {
          return l.replace(regex, match => `<span class="bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30 px-0.5 rounded">${match}</span>`);
        }).join('<br>');
      } else {
        output = `<span class="text-slate-600 italic">No matches found.</span>`;
      }
      break;
    }

    case 'nano':
    case 'vim': {
      if (args.length === 0) {
        output = `${cmd}: missing filename operand.`;
        isError = true;
        break;
      }
      const filename = args[0];
      const resolved = resolvePath(cwd, filename);
      const item = vfs[resolved];
      if (item && item.type === 'dir') {
        output = `${cmd}: ${filename}: Is a directory`;
        isError = true;
        break;
      }
      
      const currentContent = item ? item.content : "";
      req.session.gameState.editor = {
        type: cmd,
        file: resolved,
        content: currentContent
      };
      
      if (cmd === 'vim') {
        output = `\r~ \n\r~ \n\r"/${resolved.split('/').slice(1).join('/')}" 0L [New File]\n\r[VIM Simulator - Type text to append. Type ':wq' to save and exit, or ':q' to abort]`;
      } else {
        const lineCount = currentContent ? currentContent.split('\n').length : 0;
        output = `\rGNU nano 5.4                  /${resolved.split('/').slice(1).join('/')}\n\rFile: ${filename} (Lines: ${lineCount})\n\r------------------------------------------------------------\n\r[Type lines of text to append. Type 'exit' to save and exit nano.]\n\r------------------------------------------------------------`;
      }
      break;
    }

    case 'head':
    case 'tail': {
      if (args.length === 0) {
        output = `${cmd}: missing file operand`;
        isError = true;
        break;
      }
      
      let linesToShow = 10;
      let fileArg = args[0];
      if (args[0] === '-n' && args.length >= 3) {
        linesToShow = parseInt(args[1], 10) || 10;
        fileArg = args[2];
      }
      
      const resolved = resolvePath(cwd, fileArg);
      const item = vfs[resolved];
      if (!item) {
        output = `${cmd}: ${fileArg}: No such file or directory`;
        isError = true;
        break;
      }
      if (item.type === 'dir') {
        output = `${cmd}: ${fileArg}: Is a directory`;
        isError = true;
        break;
      }
      
      const lines = item.content.split('\n');
      let result = [];
      if (cmd === 'head') {
        result = lines.slice(0, linesToShow);
      } else {
        result = lines.slice(Math.max(0, lines.length - linesToShow));
      }
      output = result.join('\n');
      break;
    }

    case 'less': {
      if (args.length === 0) {
        output = "less: missing file operand";
        isError = true;
        break;
      }
      const filename = args[0];
      const resolved = resolvePath(cwd, filename);
      const item = vfs[resolved];
      if (!item) {
        output = `less: ${filename}: No such file or directory`;
        isError = true;
        break;
      }
      if (item.type === 'dir') {
        output = `less: ${filename}: Is a directory`;
        isError = true;
        break;
      }
      
      req.session.gameState.pager = {
        file: resolved,
        content: item.content,
        offset: 10
      };
      
      const lines = item.content.split('\n');
      const chunk = lines.slice(0, 10).join('\n');
      if (lines.length <= 10) {
        req.session.gameState.pager = null;
        output = chunk;
      } else {
        output = chunk + `\n<span class="text-amber-500">-- less: lines 1-10 of ${lines.length} (press ENTER to scroll, or 'q' to quit) --</span>`;
      }
      break;
    }

    default:
      output = `bash: ${cmd}: command not found`;
      isError = true;
  }

  res.json({ output, error: isError });
});

// App reset endpoint for convenience
app.post('/api/reset', (req, res) => {
  req.session.gameState = {
    level: 1,
    completedFlags: [],
    cwd: "/home/user",
    vfs: initVFS(1),
    editor: null,
    pager: null
  };
  req.session.save((err) => {
    if (err) {
      return res.status(500).json({ success: false });
    }
    return res.json({ success: true, level: 1 });
  });
});

// Start Server
app.listen(PORT, () => {
  console.log(`[✔] SERVER ACTIVE: http://localhost:${PORT}`);
});
