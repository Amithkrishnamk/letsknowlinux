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
  3: "LKL{grep_3ff1c13nt_f1lt3r1ng}",
  4: "LKL{cd_d0wn_th3_r4bb1t_h0l3}",
  5: "LKL{n4v1g4t1ng_l1nux_sys_l0gs}",
  6: "LKL{mkd1r_st4rts_th3_p4th}",
  7: "LKL{t0uch_cr34t3s_n3w_m4tt3r}",
  8: "LKL{cp_dup11c4t3s_4ll_d4t4}",
  9: "LKL{mv_r3n4m3s_4nd_tr4nsf3rs}",
  10: "LKL{rm_c1e4ns_th3_rubb1sh}",
  11: "LKL{he4d_v13ws_th3_st4rt}",
  12: "LKL{t41l_c4tch3s_th3_tr41l}",
  13: "LKL{13ss_1s_m0r3_p4g1n4t10n}",
  14: "LKL{n4n0_s1mp13_t3xt_ed1t0r}",
  15: "LKL{v1m_pr0_m0d4l_c0d1ng}",
  16: "LKL{who4m1_r3t_us3rn4m3}",
  17: "LKL{un4m3_sys_k3rn3l_1nf0}",
  18: "LKL{df_m0unt_sp4c3_ch3ck}",
  19: "LKL{chm0d_p3rm1ss10ns_sh1ft}",
  20: "LKL{ch0wn_sys_0wn3rsh1p_mod}",
  21: "LKL{sud0_gr4nts_sup3rus3r}",
  22: "LKL{w3_red1r3ct_std0ut_w1th_gt}",
  23: "LKL{4pp3nd_d4t4_w1th_d0ub13_gt}",
  24: "LKL{p1p3_c0nn3cts_cmd_str34ms}",
  25: "LKL{wc_c0unts_l1n3s_w0rds}",
  26: "LKL{rm_rf_nuk3s_wh013_tr33s}",
  27: "LKL{grep_1gn0r3s_c4s3_fl4g}",
  28: "LKL{cp_r3curs1v3_f0ld3r_dupe}",
  29: "LKL{f1nd_10c4t3s_l0st_f1l3s}",
  30: "LKL{w1ldc4rds_m4tch_p4tt3rns}",
  31: "LKL{base64_decodes_binary}",
  32: "LKL{env_st0r3s_runt1m3_vars}",
  33: "LKL{m41nfr4m3_c0r3_f1n41_r3c0v3ry}"
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

// Check if user has permission
function checkPermission(item, action, isSudo) {
  if (isSudo) return true; // root can do anything
  if (!item) return false;
  
  const owner = item.owner || 'root';
  const mode = item.mode || 'rwxr-xr-x';
  
  let allowed = false;
  if (owner === 'user') {
    if (action === 'read') allowed = mode[0] === 'r';
    if (action === 'write') allowed = mode[1] === 'w';
    if (action === 'exec') allowed = mode[2] === 'x';
  } else {
    if (action === 'read') allowed = mode[6] === 'r';
    if (action === 'write') allowed = mode[7] === 'w';
    if (action === 'exec') allowed = mode[8] === 'x';
  }
  return allowed;
}

// Expand wildcards in args
function expandWildcards(cwd, args, vfs) {
  const expanded = [];
  for (const arg of args) {
    if (arg.includes('*')) {
      const filesInCwd = [];
      Object.keys(vfs).forEach(p => {
        const parent = p.substring(0, p.lastIndexOf('/')) || '/';
        const name = p.substring(p.lastIndexOf('/') + 1);
        if (parent === cwd && name !== '.' && name !== '..') {
          filesInCwd.push(name);
        }
      });

      const regexStr = '^' + arg.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$';
      const regex = new RegExp(regexStr);

      const matches = filesInCwd.filter(f => regex.test(f));
      if (matches.length > 0) {
        expanded.push(...matches.sort());
      } else {
        expanded.push(arg);
      }
    } else {
      expanded.push(arg);
    }
  }
  return expanded;
}

// Inject level files
function injectLevelFiles(vfs, level) {
  switch (level) {
    case 2:
      vfs["/home/user/.hidden_flag"] = {
        type: "file",
        content: HIDDEN_FLAG_TEXT,
        mode: "rw-r-----",
        owner: "user",
        group: "user"
      };
      break;

    case 3:
      vfs["/home/user/access.log"] = {
        type: "file",
        content: ACCESS_LOG_TEXT,
        mode: "rw-r--r--",
        owner: "user",
        group: "user"
      };
      break;

    case 4:
      vfs["/home/user/documents"] = { type: "dir", mode: "rwxr-xr-x", owner: "user", group: "user" };
      vfs["/home/user/documents/doc.txt"] = {
        type: "file",
        content: `================================================================================
LEVEL 4 FLAG DETAILS
================================================================================
Nice navigation! You entered the documents folder successfully.

TARGET FLAG:
${FLAGS[4]}`,
        mode: "rw-r--r--",
        owner: "user",
        group: "user"
      };
      break;

    case 5:
      vfs["/var/log/sys.log"] = {
        type: "file",
        content: `2026-05-20 18:00:01 [SYSTEM] BOOT_SEQUENCE: OK
2026-05-20 18:00:03 [KERN] EXT4-fs (sda1): mounted filesystem
2026-05-20 18:01:45 [CRON] pam_unix(cron:session): session opened for root
2026-05-20 18:02:10 [SECURITY] EXTRUDER WARNING: DETECTED CORRUPTED LOGICAL ADDRESS
2026-05-20 18:02:11 [SECURITY] SECURITY BRIDGE INTRUSION RECOVERY FLAG: ${FLAGS[5]}
2026-05-20 18:03:00 [SYSTEM] DAEMON_STATUS: RUNNING`,
        mode: "rw-r--r--",
        owner: "root",
        group: "root"
      };
      break;

    case 8:
      vfs["/home/user/source.txt"] = {
        type: "file",
        content: `================================================================================
SOURCE ARCHIVE CORE DATA
================================================================================
This is the master source file. Copy it to 'backup.txt' to secure a copy.
If copy is successful, the supervisor daemon will emit the next flag.`,
        mode: "rw-r--r--",
        owner: "user",
        group: "user"
      };
      break;

    case 9:
      vfs["/home/user/old.txt"] = {
        type: "file",
        content: `================================================================================
OLD DEPRECATED CONFIGURATION
================================================================================
Rename this file to 'stable.txt' using the 'mv' command to stabilize the segment.`,
        mode: "rw-r--r--",
        owner: "user",
        group: "user"
      };
      break;

    case 10:
      vfs["/home/user/trash.txt"] = {
        type: "file",
        content: `This is trash. Please use 'rm' to delete me.`,
        mode: "rw-r--r--",
        owner: "user",
        group: "user"
      };
      break;

    case 11: {
      let confLines = ["# System configuration file", "# Do not modify", "flag_value=" + FLAGS[11]];
      for (let i = 1; i <= 30; i++) {
        confLines.push(`config.parameter.${i}=value_${i * 3}`);
      }
      vfs["/home/user/system.conf"] = {
        type: "file",
        content: confLines.join('\n'),
        mode: "rw-r--r--",
        owner: "user",
        group: "user"
      };
      break;
    }

    case 12: {
      let appLogLines = [];
      for (let i = 1; i <= 50; i++) {
        appLogLines.push(`2026-05-20 18:10:${i} [INFO] Application service tick heartbeat.`);
      }
      appLogLines.push("2026-05-20 18:11:00 [ERROR] CRITICAL STACK EXCEPTION!");
      appLogLines.push("2026-05-20 18:11:01 [SYSTEM] EMERGENCY DUMP TOKEN: " + FLAGS[12]);
      vfs["/home/user/app.log"] = {
        type: "file",
        content: appLogLines.join('\n'),
        mode: "rw-r--r--",
        owner: "user",
        group: "user"
      };
      break;
    }

    case 13: {
      let csvLines = ["id,username,role,status"];
      for (let i = 1; i <= 20; i++) {
        csvLines.push(`${i},user${i},operator,active`);
      }
      csvLines.push(`21,admin,superuser,${FLAGS[13]}`);
      for (let i = 22; i <= 40; i++) {
        csvLines.push(`${i},user${i},operator,active`);
      }
      vfs["/home/user/database.csv"] = {
        type: "file",
        content: csvLines.join('\n'),
        mode: "rw-r--r--",
        owner: "user",
        group: "user"
      };
      break;
    }

    case 14:
      vfs["/home/user/config.json"] = {
        type: "file",
        content: `{\n  "name": "letsknowlinux-core",\n  "version": "1.0.0",\n  "debug": false\n}`,
        mode: "rw-r--r--",
        owner: "user",
        group: "user"
      };
      break;

    case 15:
      vfs["/home/user/script.sh"] = {
        type: "file",
        content: `#!/bin/bash\n# Write hello script\n`,
        mode: "rw-r--r--",
        owner: "user",
        group: "user"
      };
      break;

    case 19:
      vfs["/home/user/run.sh"] = {
        type: "file",
        content: `#!/bin/bash\necho "Running core network diagnostics..."\n`,
        mode: "rw-r--r--",
        owner: "user",
        group: "user"
      };
      break;

    case 20:
      vfs["/home/user/secret.txt"] = {
        type: "file",
        content: `This file contains protected core settings. Owner should be changed to root.`,
        mode: "rw-r--r--",
        owner: "user",
        group: "user"
      };
      break;

    case 21:
      vfs["/etc/shadow"] = {
        type: "file",
        content: `root:$6$rounds=40000$saltsalt$encryptedhash:${FLAGS[21]}:0:99999:7:::
daemon:*:18749:0:99999:7:::
bin:*:18749:0:99999:7:::
user:$6$rounds=40000$userpasshash:18749:0:99999:7:::`,
        mode: "r--------",
        owner: "root",
        group: "root"
      };
      break;

    case 23:
      vfs["/home/user/patches.log"] = {
        type: "file",
        content: `patch1\n`,
        mode: "rw-r--r--",
        owner: "user",
        group: "user"
      };
      break;

    case 26:
      vfs["/home/user/old_project"] = { type: "dir", mode: "rwxr-xr-x", owner: "user", group: "user" };
      vfs["/home/user/old_project/file1.txt"] = { type: "file", content: "unused code", mode: "rw-r--r--", owner: "user", group: "user" };
      vfs["/home/user/old_project/file2.txt"] = { type: "file", content: "legacy module", mode: "rw-r--r--", owner: "user", group: "user" };
      break;

    case 27:
      vfs["/home/user/auth.log"] = {
        type: "file",
        content: `2026-05-20 18:30:11 sshd[432]: Connection from 10.0.0.15 port 43222
2026-05-20 18:30:12 sshd[432]: Failed password for invalid user SeCrEt_PaSs
2026-05-20 18:30:13 sshd[432]: SECURITY METRIC FLAG VALUE IS: ${FLAGS[27]}
2026-05-20 18:30:14 sshd[432]: Connection closed by authenticating user`,
        mode: "rw-r--r--",
        owner: "user",
        group: "user"
      };
      break;

    case 28:
      vfs["/home/user/template"] = { type: "dir", mode: "rwxr-xr-x", owner: "user", group: "user" };
      vfs["/home/user/template/index.js"] = { type: "file", content: "let a=1; console.log(a);", mode: "rw-r--r--", owner: "user", group: "user" };
      break;

    case 30:
      vfs["/home/user/part1.txt"] = { type: "file", content: "LKL{w1ld", mode: "rw-r--r--", owner: "user", group: "user" };
      vfs["/home/user/part2.txt"] = { type: "file", content: "c4rds_", mode: "rw-r--r--", owner: "user", group: "user" };
      vfs["/home/user/part3.txt"] = { type: "file", content: "m4tch_p4tt3rns}", mode: "rw-r--r--", owner: "user", group: "user" };
      break;

    case 31:
      vfs["/home/user/encoded.txt"] = {
        type: "file",
        content: "TEtMe2Jhc2U2NF9kZWNvZGVzX2JpbmFyeX0=\n",
        mode: "rw-r--r--",
        owner: "user",
        group: "user"
      };
      break;

    case 33:
      vfs["/home/user/decrypt"] = {
        type: "file",
        content: `#!/bin/bash\necho "FINAL RECOVERY FLAG: ${FLAGS[33]}"\n`,
        mode: "rw-r--r--",
        owner: "user",
        group: "user"
      };
      break;
  }
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
  
  for (let l = 2; l <= level; l++) {
    injectLevelFiles(vfs, l);
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

// Check Server-Side objectives completed to reveal flags
function checkServerObjectives(level, vfs, cmdStr, output) {
  let appendMsg = "";

  switch (level) {
    case 6:
      if (vfs["/home/user/workspace"] && vfs["/home/user/workspace"].type === 'dir') {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! Directory 'workspace' created.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{mkd1r_st4rts_th3_p4th}</span>`;
      }
      break;
    case 7:
      if (vfs["/home/user/workspace/note.txt"] && vfs["/home/user/workspace/note.txt"].type === 'file') {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! File 'note.txt' created in workspace.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{t0uch_cr34t3s_n3w_m4tt3r}</span>`;
      }
      break;
    case 8:
      if (vfs["/home/user/backup.txt"] && vfs["/home/user/backup.txt"].type === 'file') {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! File 'source.txt' copied to 'backup.txt'.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{cp_dup11c4t3s_4ll_d4t4}</span>`;
      }
      break;
    case 9:
      if (vfs["/home/user/stable.txt"] && !vfs["/home/user/old.txt"]) {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! File renamed to 'stable.txt'.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{mv_r3n4m3s_4nd_tr4nsf3rs}</span>`;
      }
      break;
    case 10:
      if (!vfs["/home/user/trash.txt"]) {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! File 'trash.txt' deleted.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{rm_c1e4ns_th3_rubb1sh}</span>`;
      }
      break;
    case 14: {
      const conf = vfs["/home/user/config.json"];
      if (conf && conf.content && conf.content.includes('"debug": true')) {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! config.json edited to set debug true.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{n4n0_s1mp13_t3xt_ed1t0r}</span>`;
      }
      break;
    }
    case 15: {
      const script = vfs["/home/user/script.sh"];
      if (script && script.content && (script.content.includes('echo "hello"') || script.content.includes('echo hello'))) {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! script.sh updated with echo.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{v1m_pr0_m0d4l_c0d1ng}</span>`;
      }
      break;
    }
    case 16: {
      const normalizedCmd16 = cmdStr.toLowerCase().replace(/\s+/g, '');
      if (normalizedCmd16.includes('whoami')) {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! Active user identity retrieved.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{who4m1_r3t_us3rn4m3}</span>`;
      }
      break;
    }
    case 17: {
      const normalizedCmd17 = cmdStr.toLowerCase().replace(/\s+/g, '');
      if (normalizedCmd17.includes('uname')) {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! Host and kernel metrics retrieved.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{un4m3_sys_k3rn3l_1nf0}</span>`;
      }
      break;
    }
    case 18: {
      const normalizedCmd18 = cmdStr.toLowerCase().replace(/\s+/g, '');
      if (normalizedCmd18.includes('df')) {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! Disk capacity metrics retrieved.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{df_m0unt_sp4c3_ch3ck}</span>`;
      }
      break;
    }
    case 19: {
      const runSh = vfs["/home/user/run.sh"];
      if (runSh && runSh.mode && runSh.mode.includes('x')) {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! run.sh set to executable.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{chm0d_p3rm1ss10ns_sh1ft}</span>`;
      }
      break;
    }
    case 20: {
      const secretTxt = vfs["/home/user/secret.txt"];
      if (secretTxt && secretTxt.owner === 'root') {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! secret.txt owner changed to root.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{ch0wn_sys_0wn3rsh1p_mod}</span>`;
      }
      break;
    }
    case 22: {
      const statusTxt = vfs["/home/user/system_status.txt"];
      if (statusTxt && statusTxt.content && statusTxt.content.includes('restore')) {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! system_status.txt updated.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{w3_red1r3ct_std0ut_w1th_gt}</span>`;
      }
      break;
    }
    case 23: {
      const patchesLog = vfs["/home/user/patches.log"];
      if (patchesLog && patchesLog.content && patchesLog.content.includes('patch2')) {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! patches.log appended.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{4pp3nd_d4t4_w1th_d0ub13_gt}</span>`;
      }
      break;
    }
    case 24: {
      const normalizedCmd24 = cmdStr.toLowerCase().replace(/\s+/g, '');
      if (normalizedCmd24.includes('|grep') && normalizedCmd24.includes('ls')) {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! ls piped to grep.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{p1p3_c0nn3cts_cmd_str34ms}</span>`;
      }
      break;
    }
    case 25: {
      const normalizedCmd25 = cmdStr.toLowerCase().replace(/\s+/g, '');
      if (normalizedCmd25.includes('|wc') && normalizedCmd25.includes('ls')) {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! ls piped to wc.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{wc_c0unts_l1n3s_w0rds}</span>`;
      }
      break;
    }
    case 26:
      if (!vfs["/home/user/old_project"]) {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! Directory 'old_project' recursively deleted.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{rm_rf_nuk3s_wh013_tr33s}</span>`;
      }
      break;
    case 28:
      if (vfs["/home/user/backup_template"] && vfs["/home/user/backup_template/index.js"]) {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! Directory 'template' recursively copied.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{cp_r3curs1v3_f0ld3r_dupe}</span>`;
      }
      break;
    case 29: {
      const normalizedCmd29 = cmdStr.toLowerCase().replace(/\s+/g, '');
      if (normalizedCmd29.includes('find') && normalizedCmd29.includes('.conf')) {
        appendMsg = `\r\n\r<span class="text-emerald-400 font-bold">[SUCCESS] Objective complete! Files located via find.</span>\r
<span class="text-amber-400 font-bold">REVEALED FLAG: LKL{f1nd_10c4t3s_l0st_f1l3s}</span>`;
      }
      break;
    }
  }

  return appendMsg;
}

// --- API ENDPOINTS ---

// Get active game state with current directory files
app.get('/api/state', (req, res) => {
  const vfs = req.session.gameState.vfs || {};
  const userFiles = [];
  const cwd = req.session.gameState.cwd || "/home/user";
  
  Object.keys(vfs).forEach(p => {
    const parent = p.substring(0, p.lastIndexOf('/')) || '/';
    const name = p.substring(p.lastIndexOf('/') + 1);
    
    if (parent === cwd) {
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
    cwd: cwd,
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

    if (currentLevel < 33) {
      nextLevel = currentLevel + 1;
      req.session.gameState.level = nextLevel;
      
      // Inject next level files into session VFS
      injectLevelFiles(req.session.gameState.vfs, nextLevel);
    } else {
      gameCompleted = true;
    }

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

// --- COMMAND PIPING, REDIRECTION, WILDCARDS & PERMISSIONS ---

function executeSingleCommand(cmdName, rawArgs, isSudo, req, pipedInput) {
  const cmd = cmdName.toLowerCase();
  const cwd = req.session.gameState.cwd || "/home/user";
  const vfs = req.session.gameState.vfs;
  
  // Expand wildcards in args
  const args = expandWildcards(cwd, rawArgs, vfs);

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

    case 'echo':
      output = args.join(' ');
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
      if (!checkPermission(item, 'read', isSudo)) {
        output = `cd: ${target}: Permission denied`;
        isError = true;
        break;
      }
      
      req.session.gameState.cwd = resolved;
      break;
    }

    case 'ls': {
      const showHidden = args.some(arg => arg.startsWith('-') && arg.includes('a'));
      const longFormat = args.some(arg => arg.startsWith('-') && arg.includes('l'));
      
      // Determine listing directory. Default is cwd.
      let targetDir = cwd;
      const nonFlagArgs = args.filter(a => !a.startsWith('-'));
      if (nonFlagArgs.length > 0) {
        targetDir = resolvePath(cwd, nonFlagArgs[0]);
      }

      const dirItem = vfs[targetDir];
      if (!dirItem) {
        output = `ls: cannot access '${nonFlagArgs[0]}': No such file or directory`;
        isError = true;
        break;
      }
      if (dirItem.type !== 'dir') {
        output = nonFlagArgs[0]; // ls on file just prints file name
        break;
      }
      if (!checkPermission(dirItem, 'read', isSudo)) {
        output = `ls: cannot open directory '${targetDir}': Permission denied`;
        isError = true;
        break;
      }

      const itemsInDir = [];
      Object.keys(vfs).forEach(p => {
        if (p === targetDir) return;
        const parent = p.substring(0, p.lastIndexOf('/')) || '/';
        const name = p.substring(p.lastIndexOf('/') + 1);
        
        if (parent === targetDir) {
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

      // Sort items alphabetically
      itemsInDir.sort((a, b) => a.name.localeCompare(b.name));

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
      if (!checkPermission(vfs[parentPath], 'write', isSudo)) {
        output = `mkdir: cannot create directory ‘${target}’: Permission denied`;
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
      if (!checkPermission(vfs[parentPath], 'write', isSudo)) {
        output = `touch: cannot touch ‘${target}’: Permission denied`;
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
      const isRecursive = args.includes('-r') || args.includes('-R') || args.includes('-rf') || args.includes('-Rf');
      const cleanArgs = args.filter(a => !a.startsWith('-'));

      if (cleanArgs.length < 2) {
        output = "cp: missing destination file operand";
        isError = true;
        break;
      }
      const src = cleanArgs[0];
      const dest = cleanArgs[1];
      
      const srcResolved = resolvePath(cwd, src);
      const srcItem = vfs[srcResolved];
      if (!srcItem) {
        output = `cp: cannot stat ‘${src}’: No such file or directory`;
        isError = true;
        break;
      }

      if (!checkPermission(srcItem, 'read', isSudo)) {
        output = `cp: cannot open ‘${src}’: Permission denied`;
        isError = true;
        break;
      }
      
      if (srcItem.type === 'dir' && !isRecursive) {
        output = `cp: -r not specified; omitting directory ‘${src}’`;
        isError = true;
        break;
      }
      
      let destResolved = resolvePath(cwd, dest);
      const destItem = vfs[destResolved];
      
      if (srcItem.type === 'dir' && isRecursive) {
        let targetDestBase = destResolved;
        if (destItem && destItem.type === 'dir') {
          const folderName = srcResolved.split('/').pop();
          targetDestBase = path.posix.join(destResolved, folderName);
        }

        vfs[targetDestBase] = {
          type: "dir",
          mode: srcItem.mode || "rwxr-xr-x",
          owner: isSudo ? "root" : "user",
          group: isSudo ? "user" : "user"
        };

        const prefix = srcResolved + '/';
        Object.keys(vfs).forEach(p => {
          if (p.startsWith(prefix)) {
            const relPath = p.substring(prefix.length);
            const targetPath = path.posix.join(targetDestBase, relPath);
            vfs[targetPath] = {
              ...vfs[p],
              owner: isSudo ? "root" : vfs[p].owner,
              group: isSudo ? "user" : vfs[p].group
            };
          }
        });
      } else {
        if (destItem && destItem.type === 'dir') {
          const filename = srcResolved.split('/').pop();
          destResolved = path.posix.join(destResolved, filename);
        }

        const destParent = destResolved.substring(0, destResolved.lastIndexOf('/')) || '/';
        if (!vfs[destParent] || vfs[destParent].type !== 'dir') {
          output = `cp: cannot create regular file ‘${dest}’: No such file or directory`;
          isError = true;
          break;
        }
        if (!checkPermission(vfs[destParent], 'write', isSudo)) {
          output = `cp: cannot create regular file ‘${dest}’: Permission denied`;
          isError = true;
          break;
        }

        vfs[destResolved] = {
          type: "file",
          content: srcItem.content,
          mode: srcItem.mode,
          owner: isSudo ? "root" : "user",
          group: isSudo ? "user" : "user"
        };
      }
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

      if (!checkPermission(srcItem, 'write', isSudo)) {
        output = `mv: cannot move ‘${src}’: Permission denied`;
        isError = true;
        break;
      }
      
      let destResolved = resolvePath(cwd, dest);
      const destItem = vfs[destResolved];
      if (destItem && destItem.type === 'dir') {
        const filename = srcResolved.split('/').pop();
        destResolved = path.posix.join(destResolved, filename);
      }

      const destParent = destResolved.substring(0, destResolved.lastIndexOf('/')) || '/';
      if (!vfs[destParent] || vfs[destParent].type !== 'dir') {
        output = `mv: cannot move to ‘${dest}’: No such file or directory`;
        isError = true;
        break;
      }
      if (!checkPermission(vfs[destParent], 'write', isSudo)) {
        output = `mv: cannot move to ‘${dest}’: Permission denied`;
        isError = true;
        break;
      }
      
      if (srcItem.type === 'dir') {
        vfs[destResolved] = srcItem;
        delete vfs[srcResolved];
        const prefix = srcResolved + '/';
        Object.keys(vfs).forEach(p => {
          if (p.startsWith(prefix)) {
            const relative = p.substring(prefix.length);
            const newPath = path.posix.join(destResolved, relative);
            vfs[newPath] = vfs[p];
            delete vfs[p];
          }
        });
      } else {
        vfs[destResolved] = srcItem;
        delete vfs[srcResolved];
      }
      break;
    }

    case 'rm': {
      if (args.length === 0) {
        output = "rm: missing operand";
        isError = true;
        break;
      }
      
      const isRecursive = args.includes('-r') || args.includes('-rf') || args.includes('-R') || (args.includes('-f') && args.includes('-r'));
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

      if (!checkPermission(item, 'write', isSudo)) {
        output = `rm: cannot remove ‘${target}’: Permission denied`;
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

      if (vfs[resolved].owner !== 'user' && !isSudo) {
        output = `chmod: changing permissions of ‘${target}’: Operation not permitted`;
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

      if (!isSudo) {
        output = `chown: changing ownership of ‘${target}’: Operation not permitted`;
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
      const cleanArgs = args.filter(a => !a.startsWith('-'));
      if (cleanArgs.length === 0) {
        if (pipedInput !== null) {
          output = pipedInput;
        } else {
          output = "cat: missing file operand. Usage: cat [filename]";
          isError = true;
        }
        break;
      }

      let catOutputs = [];
      let catError = false;
      for (const target of cleanArgs) {
        const resolved = resolvePath(cwd, target);
        const item = vfs[resolved];
        if (!item) {
          catOutputs.push(`cat: ${target}: No such file or directory`);
          catError = true;
          continue;
        }
        if (item.type === 'dir') {
          catOutputs.push(`cat: ${target}: Is a directory`);
          catError = true;
          continue;
        }
        if (!checkPermission(item, 'read', isSudo)) {
          catOutputs.push(`cat: ${target}: Permission denied`);
          catError = true;
          continue;
        }
        
        if (resolved.endsWith('access.log')) {
          const lineCount = item.content.split('\n').length;
          catOutputs.push(`<div class="text-slate-500 border-l border-amber-500/20 pl-2 text-xs h-64 overflow-y-auto font-mono scroll-smooth mb-2">${item.content}</div>
<span class="text-amber-500 font-bold">[SYSTEM WARNING] Buffer overflow risk avoided!</span>\r
Printed ${lineCount} log lines. Searching manually is inefficient.\r
Use '<span class="text-yellow-400 font-bold">grep</span>' to filter specific records.\r
Example: <span class="text-yellow-400">grep "FLAG" access.log</span>`);
        } else {
          catOutputs.push(item.content);
        }
      }

      output = catOutputs.join('\n');
      if (catError) {
        isError = true;
      }
      break;
    }

    case 'grep': {
      let isCaseInsensitive = false;
      const flags = args.filter(a => a.startsWith('-'));
      if (flags.includes('-i') || flags.includes('--ignore-case')) {
        isCaseInsensitive = true;
      }

      const cleanArgs = args.filter(a => !a.startsWith('-'));

      if (cleanArgs.length === 0) {
        output = "grep: missing search pattern. Usage: grep [pattern] [filename]";
        isError = true;
        break;
      }

      const pattern = cleanArgs[0];
      let contentToSearch = "";

      if (cleanArgs.length === 1) {
        if (pipedInput !== null) {
          contentToSearch = pipedInput;
        } else {
          output = "grep: missing file operand. Usage: grep [pattern] [filename]";
          isError = true;
          break;
        }
      } else {
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
        if (!checkPermission(item, 'read', isSudo)) {
          output = `grep: ${filename}: Permission denied`;
          isError = true;
          break;
        }
        contentToSearch = item.content;
      }
      
      const lines = contentToSearch.split('\n');
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

      if (item && !checkPermission(item, 'write', isSudo)) {
        output = `${cmd}: ${filename}: Permission denied`;
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
      let linesToShow = 10;
      let fileArg = null;

      let cleanArgs = [];
      for (let i = 0; i < args.length; i++) {
        if (args[i] === '-n' && i + 1 < args.length) {
          linesToShow = parseInt(args[i+1], 10) || 10;
          i++;
        } else if (args[i].startsWith('-n') && args[i].length > 2) {
          linesToShow = parseInt(args[i].substring(2), 10) || 10;
        } else {
          cleanArgs.push(args[i]);
        }
      }

      if (cleanArgs.length > 0) {
        fileArg = cleanArgs[0];
      }

      let contentToProcess = "";
      if (!fileArg) {
        if (pipedInput !== null) {
          contentToProcess = pipedInput;
        } else {
          output = `${cmd}: missing file operand`;
          isError = true;
          break;
        }
      } else {
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
        if (!checkPermission(item, 'read', isSudo)) {
          output = `${cmd}: ${fileArg}: Permission denied`;
          isError = true;
          break;
        }
        contentToProcess = item.content;
      }
      
      const lines = contentToProcess.split('\n');
      let resultLines = [];
      if (cmd === 'head') {
        resultLines = lines.slice(0, linesToShow);
      } else {
        resultLines = lines.slice(Math.max(0, lines.length - linesToShow));
      }
      output = resultLines.join('\n');
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
      if (!checkPermission(item, 'read', isSudo)) {
        output = `less: ${filename}: Permission denied`;
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

    case 'wc': {
      let linesOnly = args.includes('-l');
      let wordsOnly = args.includes('-w');
      let bytesOnly = args.includes('-c');
      
      if (!linesOnly && !wordsOnly && !bytesOnly) {
        linesOnly = true;
        wordsOnly = true;
        bytesOnly = true;
      }

      const cleanArgs = args.filter(a => !a.startsWith('-'));
      let contentToProcess = "";
      let label = "";

      if (cleanArgs.length === 0) {
        if (pipedInput !== null) {
          contentToProcess = pipedInput;
        } else {
          output = "wc: missing file operand";
          isError = true;
          break;
        }
      } else {
        const filename = cleanArgs[0];
        const resolved = resolvePath(cwd, filename);
        const item = vfs[resolved];
        if (!item) {
          output = `wc: ${filename}: No such file or directory`;
          isError = true;
          break;
        }
        if (item.type === 'dir') {
          output = `wc: ${filename}: Is a directory`;
          isError = true;
          break;
        }
        if (!checkPermission(item, 'read', isSudo)) {
          output = `wc: ${filename}: Permission denied`;
          isError = true;
          break;
        }
        contentToProcess = item.content;
        label = filename;
      }

      const linesCount = contentToProcess ? contentToProcess.split('\n').length - (contentToProcess.endsWith('\n') ? 1 : 0) : 0;
      const wordsCount = contentToProcess ? contentToProcess.split(/\s+/).filter(Boolean).length : 0;
      const bytesCount = Buffer.byteLength(contentToProcess || "");

      const resultParts = [];
      if (linesOnly) resultParts.push(linesCount);
      if (wordsOnly) resultParts.push(wordsCount);
      if (bytesOnly) resultParts.push(bytesCount);
      if (label) resultParts.push(label);

      output = resultParts.join(' ');
      break;
    }

    case 'find': {
      let searchDir = cwd;
      let namePattern = null;

      let cleanArgs = [];
      for (let i = 0; i < args.length; i++) {
        if (args[i] === '-name' && i + 1 < args.length) {
          namePattern = args[i+1];
          i++;
        } else {
          cleanArgs.push(args[i]);
        }
      }

      if (cleanArgs.length > 0) {
        searchDir = resolvePath(cwd, cleanArgs[0]);
      }

      const dirItem = vfs[searchDir];
      if (!dirItem) {
        output = `find: ‘${cleanArgs[0]}’: No such file or directory`;
        isError = true;
        break;
      }

      const matchedPaths = [];
      Object.keys(vfs).forEach(p => {
        if (p === searchDir) {
          const baseName = p.substring(p.lastIndexOf('/') + 1) || '/';
          if (!namePattern || matchPattern(baseName, namePattern)) {
            matchedPaths.push(p);
          }
          return;
        }

        if (p.startsWith(searchDir === '/' ? '/' : searchDir + '/')) {
          const baseName = p.substring(p.lastIndexOf('/') + 1);
          if (!namePattern || matchPattern(baseName, namePattern)) {
            matchedPaths.push(p);
          }
        }
      });

      function matchPattern(str, pat) {
        let cleanPat = pat;
        if ((pat.startsWith('"') && pat.endsWith('"')) || (pat.startsWith("'") && pat.endsWith("'"))) {
          cleanPat = pat.substring(1, pat.length - 1);
        }
        const regexStr = '^' + cleanPat.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$';
        return new RegExp(regexStr).test(str);
      }

      output = matchedPaths.sort().join('\n');
      break;
    }

    case 'base64': {
      const isDecode = args.includes('-d') || args.includes('--decode');
      const cleanArgs = args.filter(a => !a.startsWith('-'));

      let inputData = "";
      if (cleanArgs.length === 0) {
        if (pipedInput !== null) {
          inputData = pipedInput;
        } else {
          output = "base64: missing input operand";
          isError = true;
          break;
        }
      } else {
        const filename = cleanArgs[0];
        const resolved = resolvePath(cwd, filename);
        const item = vfs[resolved];
        if (!item) {
          output = `base64: ${filename}: No such file or directory`;
          isError = true;
          break;
        }
        if (item.type === 'dir') {
          output = `base64: ${filename}: Is a directory`;
          isError = true;
          break;
        }
        if (!checkPermission(item, 'read', isSudo)) {
          output = `base64: ${filename}: Permission denied`;
          isError = true;
          break;
        }
        inputData = item.content;
      }

      if (isDecode) {
        try {
          output = Buffer.from(inputData.trim(), 'base64').toString('utf8');
        } catch (e) {
          output = "base64: invalid input";
          isError = true;
        }
      } else {
        output = Buffer.from(inputData).toString('base64') + '\n';
      }
      break;
    }

    case 'env': {
      const envVars = {
        "SHELL": "/bin/bash",
        "USER": isSudo ? "root" : "user",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PWD": cwd,
        "HOME": "/home/user",
        "FLAG_ENV": FLAGS[32]
      };
      output = Object.entries(envVars).map(([k, v]) => `${k}=${v}`).join('\n');
      break;
    }

    default:
      let executablePath = null;
      if (rawArgs.length === 0 && (cmdName.startsWith('./') || cmdName.startsWith('/'))) {
        executablePath = resolvePath(cwd, cmdName);
      }

      if (executablePath && vfs[executablePath]) {
        const execItem = vfs[executablePath];
        if (execItem.type === 'dir') {
          output = `bash: ${cmdName}: Is a directory`;
          isError = true;
          break;
        }

        if (!checkPermission(execItem, 'exec', isSudo)) {
          output = `bash: ${cmdName}: Permission denied`;
          isError = true;
          break;
        }

        if (executablePath === "/home/user/decrypt") {
          output = `FINAL RECOVERY FLAG: ${FLAGS[33]}`;
        } else if (execItem.content) {
          if (execItem.content.startsWith('#!/bin/bash') || execItem.content.startsWith('#!/bin/sh')) {
            const lines = execItem.content.split('\n').slice(1);
            let stdout = "";
            for (const line of lines) {
              const trimmed = line.trim();
              if (trimmed && !trimmed.startsWith('#')) {
                if (trimmed.startsWith('echo ')) {
                  let echoContent = trimmed.substring(5).trim();
                  if ((echoContent.startsWith('"') && echoContent.endsWith('"')) || 
                      (echoContent.startsWith("'") && echoContent.endsWith("'"))) {
                    echoContent = echoContent.substring(1, echoContent.length - 1);
                  }
                  echoContent = echoContent.replace(/\$FLAGS\[33\]/g, FLAGS[33])
                                           .replace(/\$FLAGS\[31\]/g, FLAGS[31]);
                  stdout += echoContent + '\n';
                }
              }
            }
            output = stdout.trim();
          } else {
            output = execItem.content;
          }
        } else {
          output = "";
        }
      } else {
        output = `bash: ${cmdName}: command not found`;
        isError = true;
      }
  }

  return { output, error: isError };
}

function executeCommandLine(commandLine, req) {
  let redirectOp = null;
  let redirectFile = null;
  let cmdPart = commandLine;

  let inDoubleQuotes = false;
  let inSingleQuotes = false;
  for (let i = commandLine.length - 1; i >= 0; i--) {
    const char = commandLine[i];
    if (char === '"' && (i === 0 || commandLine[i-1] !== '\\')) {
      inDoubleQuotes = !inDoubleQuotes;
    } else if (char === "'" && (i === 0 || commandLine[i-1] !== '\\')) {
      inSingleQuotes = !inSingleQuotes;
    }

    if (!inDoubleQuotes && !inSingleQuotes) {
      if (char === '>') {
        if (i > 0 && commandLine[i-1] === '>') {
          redirectOp = '>>';
          redirectFile = commandLine.substring(i + 1).trim();
          cmdPart = commandLine.substring(0, i - 1).trim();
          break;
        } else {
          redirectOp = '>';
          redirectFile = commandLine.substring(i + 1).trim();
          cmdPart = commandLine.substring(0, i).trim();
          break;
        }
      }
    }
  }

  const pipeSegments = [];
  let currentSegment = "";
  inDoubleQuotes = false;
  inSingleQuotes = false;
  for (let i = 0; i < cmdPart.length; i++) {
    const char = cmdPart[i];
    if (char === '"' && (i === 0 || cmdPart[i-1] !== '\\')) {
      inDoubleQuotes = !inDoubleQuotes;
      currentSegment += char;
    } else if (char === "'" && (i === 0 || cmdPart[i-1] !== '\\')) {
      inSingleQuotes = !inSingleQuotes;
      currentSegment += char;
    } else if (char === '|' && !inDoubleQuotes && !inSingleQuotes) {
      pipeSegments.push(currentSegment.trim());
      currentSegment = "";
    } else {
      currentSegment += char;
    }
  }
  pipeSegments.push(currentSegment.trim());

  let pipedInput = null;
  let finalResult = { output: "", error: false };

  for (let i = 0; i < pipeSegments.length; i++) {
    const segment = pipeSegments[i];
    if (!segment) {
      return { output: "bash: syntax error near unexpected token `|'", error: true };
    }

    let tokens = parseCommandArgs(segment);
    if (tokens.length === 0) {
      return { output: "bash: syntax error near unexpected token `|'", error: true };
    }

    let isSudo = false;
    if (tokens[0] === 'sudo') {
      isSudo = true;
      tokens = tokens.slice(1);
    }

    if (tokens.length === 0) {
      return { output: "usage: sudo [command]", error: true };
    }

    const cmd = tokens[0];
    const args = tokens.slice(1);

    finalResult = executeSingleCommand(cmd, args, isSudo, req, pipedInput);
    if (finalResult.error) {
      return finalResult;
    }
    pipedInput = finalResult.output;
  }

  if (redirectOp && redirectFile) {
    if ((redirectFile.startsWith('"') && redirectFile.endsWith('"')) || 
        (redirectFile.startsWith("'") && redirectFile.endsWith("'"))) {
      redirectFile = redirectFile.substring(1, redirectFile.length - 1);
    }
    const cwd = req.session.gameState.cwd || "/home/user";
    const resolved = resolvePath(cwd, redirectFile);
    const vfs = req.session.gameState.vfs;

    const parentPath = resolved.substring(0, resolved.lastIndexOf('/')) || '/';
    if (!vfs[parentPath] || vfs[parentPath].type !== 'dir') {
      return { output: `bash: ${redirectFile}: No such file or directory`, error: true };
    }
    if (!checkPermission(vfs[parentPath], 'write', false)) {
      return { output: `bash: ${redirectFile}: Permission denied`, error: true };
    }

    const existingFile = vfs[resolved];
    if (existingFile && existingFile.type === 'dir') {
      return { output: `bash: ${redirectFile}: Is a directory`, error: true };
    }
    if (existingFile && !checkPermission(existingFile, 'write', false)) {
      return { output: `bash: ${redirectFile}: Permission denied`, error: true };
    }

    let fileContent = finalResult.output;
    const cleanContent = fileContent.replace(/<[^>]*>/g, '');

    if (redirectOp === '>') {
      vfs[resolved] = {
        type: "file",
        content: cleanContent,
        mode: existingFile ? existingFile.mode : "rw-r--r--",
        owner: existingFile ? existingFile.owner : "user",
        group: existingFile ? existingFile.group : "user"
      };
    } else {
      const originalContent = existingFile ? existingFile.content : "";
      vfs[resolved] = {
        type: "file",
        content: originalContent + (originalContent && !originalContent.endsWith('\n') ? '\n' : '') + cleanContent,
        mode: existingFile ? existingFile.mode : "rw-r--r--",
        owner: existingFile ? existingFile.owner : "user",
        group: existingFile ? existingFile.group : "user"
      };
    }

    return { output: "", error: false };
  }

  return finalResult;
}

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

  // Run through pipe/redirection parser
  let result = executeCommandLine(sanitized, req);

  // Check if objectives are satisfied
  const level = req.session.gameState.level;
  const vfs = req.session.gameState.vfs;
  const appendMsg = checkServerObjectives(level, vfs, sanitized, result.output);
  if (appendMsg) {
    result.output += appendMsg;
  }

  res.json({ output: result.output, error: result.error });
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
