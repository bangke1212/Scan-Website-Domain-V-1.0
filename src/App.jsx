import React, { useState, useMemo, useRef } from 'react';
import {
  Shield, ShieldAlert, ShieldCheck, ShieldX, Search, AlertTriangle,
  CheckCircle2, XCircle, Info, Copy, Loader2, History, Trash2, Link2,
  Coins, FileCode2, Globe, Zap, Eye, ChevronRight, TrendingUp, Lock,
  AlertOctagon, Sparkles
} from 'lucide-react';
import './App.css';

const C = {
  primary: '#00C897',
  secondary: '#1A1A2E',
  bg: '#121212',
  danger: '#E94560',
  text: '#EAEAEA',
  card: '#16213E',
  muted: '#8A93A6',
  border: '#243056',
  amber: '#FFB020',
};

const KNOWN_SCAM_KEYWORDS = [
  'airdrop-claim', 'free-tokens', 'double-your', 'giveaway', 'connect-wallet-verify',
  'wallet-recovery', 'seed-phrase', 'private-key', 'metamask-support', 'validate-wallet',
  'claim-reward', 'nft-mint-live', 'presale-live', 'urgent-migration', 'connect-wallet',
  'verify-account', 'withdrawal-error', 'migration-live'
];

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.click', '.link', '.gq', '.tk', '.ml', '.cf', '.buzz', '.icu', '.rest'];
const TRUSTED_DOMAINS = ['etherscan.io', 'coingecko.com', 'coinmarketcap.com', 'binance.com', 'coinbase.com', 'uniswap.org', 'metamask.io', 'ledger.com', 'trezor.io', 'opensea.io', 'pancakeswap.finance', 'aave.com', 'solscan.io', 'magiceden.io'];
const HIGH_RISK_TOKEN_NAMES = ['safemoon', 'shibafloki', 'elonmars', 'trumpcoin', 'bitconnect', 'squidgame', 'airdrop', 'presale'];

function detectInputType(raw) {
  const q = String(raw ?? '').trim();
  if (!q) return { type: 'empty', normalized: '' };
  if (/^0x[a-fA-F0-9]{40}$/.test(q)) return { type: 'address', chain: 'evm', normalized: q };
  if (/^0x[a-fA-F0-9]{64}$/.test(q)) return { type: 'txhash', chain: 'evm', normalized: q };
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(q) && !q.startsWith('0x')) return { type: 'address', chain: 'solana', normalized: q };
  if (/^(https?:\/\/|www\.)/i.test(q) || /^[a-z0-9][a-z0-9-]*\.[a-z]{2,}(\/.*)?$/i.test(q)) {
    let url = q.startsWith('http') ? q : 'https://' + q;
    return { type: 'url', normalized: url };
  }
  return { type: 'token', normalized: q };
}

function analyzeAddress(addr, chain) {
  const flags = [];
  const a = addr.toLowerCase();
  flags.push({ level: 'positive', title: 'Valid address format', detail: `Recognized as a well-formed ${chain === 'evm' ? 'EVM' : 'Solana'} address.` });
  if (/^0x0{20,}/.test(a)) flags.push({ level: 'critical', title: 'Burn / null address', detail: 'This is the zero-address — tokens sent here are unrecoverable.' });
  if (/^0xdead/i.test(a) || /0{10,}dead/i.test(a)) flags.push({ level: 'high', title: 'Known burn address pattern', detail: 'Address matches common burn-address patterns (e.g. 0x…dead).' });
  if (/(.)\1{7,}/.test(a.slice(2))) flags.push({ level: 'medium', title: 'Suspicious vanity pattern', detail: 'Long repeating character sequence — often used in low-effort scam deployments.' });
  const uniqueChars = new Set(a.slice(2).split('')).size;
  if (uniqueChars < 6) flags.push({ level: 'high', title: 'Low character entropy', detail: `Only ${uniqueChars} unique characters — real contract addresses typically use 12+.` });
  else flags.push({ level: 'info', title: 'Entropy check passed', detail: `${uniqueChars} unique characters — consistent with a normal deployed contract.` });
  flags.push({ level: 'info', title: 'On-chain verification not performed', detail: 'This tool runs a static heuristic check only. Always cross-check the address on Etherscan / Solscan and confirm the token is verified before trading.' });
  return flags;
}

function analyzeUrl(rawUrl) {
  const flags = [];
  let host = '', path = '';
  try { const u = new URL(rawUrl); host = u.hostname.toLowerCase(); path = u.pathname.toLowerCase() + u.search.toLowerCase(); }
  catch { flags.push({ level: 'high', title: 'Malformed URL', detail: 'The URL could not be parsed — this is unusual for a legitimate site.' }); return flags; }
  if (rawUrl.startsWith('http://')) flags.push({ level: 'high', title: 'No HTTPS encryption', detail: 'This site does not use HTTPS. Never enter wallet data on unencrypted pages.' });
  else flags.push({ level: 'positive', title: 'HTTPS enabled', detail: 'Traffic to this site is encrypted (TLS).' });
  const trusted = TRUSTED_DOMAINS.find(d => host === d || host.endsWith('.' + d));
  if (trusted) flags.push({ level: 'positive', title: `Recognized as ${trusted}`, detail: 'Domain matches a well-known, established crypto service.' });
  const badTld = SUSPICIOUS_TLDS.find(t => host.endsWith(t));
  if (badTld && !trusted) flags.push({ level: 'high', title: `Suspicious TLD: ${badTld}`, detail: `${badTld} domains are cheap and frequently used by short-lived scam sites.` });
  const typoTargets = ['metamask', 'uniswap', 'etherscan', 'binance', 'coinbase', 'trezor', 'ledger', 'opensea', 'phantom', 'pancakeswap', '1inch', 'solflare'];
  for (const target of typoTargets) {
    if (host.includes(target) && !TRUSTED_DOMAINS.some(d => host === d || host.endsWith('.' + d))) {
      flags.push({ level: 'critical', title: `Possible typosquat of "${target}"`, detail: `Domain contains "${target}" but is not the official domain. Classic phishing pattern.` });
      break;
    }
  }
  const kwHits = KNOWN_SCAM_KEYWORDS.filter(k => host.includes(k) || path.includes(k));
  if (kwHits.length) flags.push({ level: 'high', title: `Scam keywords detected (${kwHits.length})`, detail: `Matches: ${kwHits.slice(0, 3).join(', ')}. Legit projects rarely need "verify wallet" or "claim reward" URLs.` });
  const subCount = host.split('.').length - 2;
  if (subCount >= 3) flags.push({ level: 'medium', title: 'Deep subdomain nesting', detail: `${subCount + 1} subdomain levels — phishers use deep subdomains to hide the real registered domain.` });
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) flags.push({ level: 'critical', title: 'Raw IP address as host', detail: 'Site is served directly from an IP — legitimate crypto services always use a proper domain.' });
  if (host.startsWith('xn--')) flags.push({ level: 'critical', title: 'Punycode (IDN) domain', detail: 'Internationalized domain name — frequently abused to mimic real brands (e.g. "еthereum" with a Cyrillic e).' });
  if (host.length > 40) flags.push({ level: 'medium', title: 'Unusually long hostname', detail: `${host.length} characters — long domains are commonly generated for scam campaigns.` });
  const dashes = (host.match(/-/g) || []).length;
  if (dashes >= 3) flags.push({ level: 'low', title: `Many hyphens in domain (${dashes})`, detail: 'Multiple hyphens can indicate keyword-stuffed scam domains.' });
  flags.push({ level: 'info', title: 'WHOIS / age not checked', detail: 'For a full audit also verify domain age, SSL issuer and reputation on scamadviser.com or urlscan.io.' });
  return flags;
}

function analyzeToken(name) {
  const flags = [];
  const n = name.toLowerCase();
  flags.push({ level: 'info', title: 'Symbolic lookup only', detail: 'Token names are not unique. Anyone can deploy a token called "USDT" — always verify by contract address, not name.' });
  if (n.length < 3) flags.push({ level: 'medium', title: 'Very short token name', detail: 'Extremely short names are hard to disambiguate and often used in impersonation.' });
  const hits = HIGH_RISK_TOKEN_NAMES.filter(k => n.includes(k));
  if (hits.length) flags.push({ level: 'high', title: `Matches risky pattern: ${hits.join(', ')}`, detail: 'This name pattern is historically associated with high-loss projects, rugpulls, or meme scams.' });
  const hype = ['moon', 'inu', 'elon', 'trump', 'safe', 'baby', 'mega', 'x100', '1000x', 'pump'];
  const hypeHits = hype.filter(w => n.includes(w));
  if (hypeHits.length >= 2) flags.push({ level: 'high', title: 'Multiple hype markers', detail: `Contains: ${hypeHits.join(', ')}. Legit projects rarely stack multiple hype words.` });
  else if (hypeHits.length === 1) flags.push({ level: 'medium', title: `Contains hype word "${hypeHits[0]}"`, detail: 'Not automatically a scam, but common in short-lived meme launches.' });
  if (/(x|100|1000)\s*x/i.test(n) || /100+x/i.test(n)) flags.push({ level: 'high', title: 'Return-multiplier in the name', detail: '"100x", "1000x", etc. are marketing gimmicks, not project features. Treat with extreme skepticism.' });
  const majors = { btc: 'Bitcoin', bitcoin: 'Bitcoin', eth: 'Ethereum', ethereum: 'Ethereum', usdt: 'Tether', usdc: 'USD Coin', bnb: 'BNB', sol: 'Solana' };
  for (const [k, v] of Object.entries(majors)) {
    if (n === k) { flags.push({ level: 'positive', title: `Recognized major asset: ${v}`, detail: `${v} is one of the largest, most liquid assets. Still verify you are trading the real contract, not a fake copy.` }); break; }
  }
  return flags;
}

const WEIGHT = { critical: 40, high: 20, medium: 8, low: 3, info: 0, positive: -5 };
function scoreFlags(flags) {
  let score = 0;
  for (const f of flags) score += WEIGHT[f.level] || 0;
  score = Math.max(0, Math.min(100, score));
  let level = 'Low';
  if (score >= 60) level = 'Critical';
  else if (score >= 35) level = 'High';
  else if (score >= 15) level = 'Medium';
  return { score, level };
}

function runAnalysis(rawInput) {
  const det = detectInputType(rawInput);
  if (det.type === 'empty') return null;
  let flags = [];
  if (det.type === 'address') flags = analyzeAddress(det.normalized, det.chain);
  else if (det.type === 'txhash') flags = [{ level: 'info', title: 'Transaction hash detected', detail: 'This is a transaction hash, not a contract address. Look it up directly on the corresponding block explorer.' }];
  else if (det.type === 'url') flags = analyzeUrl(det.normalized);
  else flags = analyzeToken(det.normalized);
  const { score, level } = scoreFlags(flags);
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4, positive: 5 };
  flags.sort((a, b) => (order[a.level] ?? 9) - (order[b.level] ?? 9));
  return { input: rawInput, ...det, flags, score, level };
}

const FLAG_STYLE = {
  critical: { color: C.danger,  bg: 'rgba(233,69,96,0.10)',  border: 'rgba(233,69,96,0.30)',  Icon: AlertOctagon, label: 'CRITICAL' },
  high:     { color: C.danger,  bg: 'rgba(233,69,96,0.08)',  border: 'rgba(233,69,96,0.22)',  Icon: AlertTriangle,label: 'HIGH' },
  medium:   { color: C.amber,   bg: 'rgba(255,176,32,0.10)', border: 'rgba(255,176,32,0.28)', Icon: AlertTriangle,label: 'MEDIUM' },
  low:      { color: C.amber,   bg: 'rgba(255,176,32,0.06)', border: 'rgba(255,176,32,0.18)', Icon: Info,         label: 'LOW' },
  info:     { color: C.muted,   bg: 'rgba(138,147,166,0.08)',border: 'rgba(138,147,166,0.20)',Icon: Info,         label: 'INFO' },
  positive: { color: C.primary, bg: 'rgba(0,200,151,0.08)',  border: 'rgba(0,200,151,0.25)',  Icon: CheckCircle2, label: 'PASS' },
};

const LEVEL_STYLE = {
  Low:      { color: C.primary, Icon: ShieldCheck, label: 'LOW RISK',      msg: 'No major red flags detected. Still do your own research before investing.' },
  Medium:   { color: C.amber,   Icon: Shield,      label: 'MEDIUM RISK',   msg: 'Some warning signs found. Proceed with caution and verify further.' },
  High:     { color: C.danger,  Icon: ShieldAlert, label: 'HIGH RISK',     msg: 'Multiple serious red flags detected. Do NOT connect your wallet or send funds until you have independently verified everything.' },
  Critical: { color: C.danger,  Icon: ShieldX,     label: 'CRITICAL RISK', msg: 'Highly likely to be a scam or phishing operation. Do not interact under any circumstances.' },
};

const TYPE_STYLE = {
  address: { Icon: FileCode2, label: 'Contract Address', color: C.primary },
  txhash:  { Icon: Link2,     label: 'Transaction Hash', color: C.primary },
  url:     { Icon: Globe,     label: 'Website URL',      color: C.amber },
  token:   { Icon: Coins,     label: 'Token Name',       color: C.amber },
};

export default function App() {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [view, setView] = useState('scan');
  const [copied, setCopied] = useState(false);
  const [history, setHistory] = useState([]);

  const stats = useMemo(() => {
    const total = history.length;
    const critical = history.filter(r => r.risk_level === 'Critical').length;
    const high = history.filter(r => r.risk_level === 'High').length;
    const clean = history.filter(r => r.risk_level === 'Low').length;
    return { total, critical, high, clean };
  }, [history]);

  async function handleScan() {
    const raw = input.trim();
    if (!raw) return;
    setScanning(true);
    setResult(null);
    await new Promise(r => setTimeout(r, 450));
    const r = runAnalysis(raw);
    setResult(r);
    setScanning(false);
    if (r) {
      setHistory(prev => {
        const row = { id: Date.now(), query: raw.slice(0, 200), input_type: r.type === 'txhash' ? 'address' : r.type, risk_level: r.level, risk_score: r.score, flags_count: r.flags.length, scanned_at: new Date().toISOString() };
        return [row, ...prev].slice(0, 50);
      });
    }
  }

  function handleSubmit(e) {
    e.preventDefault();
    handleScan();
  }

  function loadExample(ex) { setInput(ex); setResult(null); }

  async function copyInput() {
    if (!result) return;
    try { await navigator.clipboard.writeText(result.normalized); setCopied(true); setTimeout(() => setCopied(false), 1600); } catch {}
  }

  function clearOne(id) { setHistory(prev => prev.filter(h => h.id !== id)); }

  const level = result ? LEVEL_STYLE[result.level] : null;
  const typeStyle = result ? TYPE_STYLE[result.type] || TYPE_STYLE.token : null;
  const flagCounts = result ? result.flags.reduce((acc, f) => { acc[f.level] = (acc[f.level] || 0) + 1; return acc; }, {}) : {};

  return (
    <div className="app-container">
      <div className="header">
        <div className="header-inner">
          <div className="brand">
            <div className="brand-icon"><Shield size={20} color={C.primary} /></div>
            <div>
              <h1>CryptoGuard</h1>
              <p>Scam & risk analyzer</p>
            </div>
          </div>
          <div className="tabs">
            {[{ id: 'scan', icon: Search, label: 'Scan' },{ id: 'history', icon: History, label: 'History' },].map(t => {
              const Icon = t.icon;
              const active = view === t.id;
              return (
                <button key={t.id} onClick={() => setView(t.id)} className={'tab-btn' + (active ? ' active' : '')}>
                  <Icon size={12} />{t.label}
                  {t.id === 'history' && history.length > 0 && <span className="tab-badge">{history.length}</span>}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      <div className="content">
        {view === 'scan' && (
          <div className="scan-view">
            <div className="hero-card">
              <div className="hero-badge"><Sparkles size={14} color={C.primary} /><span>Instant analysis</span></div>
              <h2>Check any token, contract or site.</h2>
              <p>Paste a contract address, token name, or website URL to get a risk score and a list of red flags — before you connect your wallet.</p>
              <form onSubmit={handleSubmit} className="scan-form">
                <div className="input-wrap">
                  <Search size={16} className="input-icon" />
                  <input value={input} onChange={e => setInput(e.target.value)} placeholder="0xdac17f… · uniswap.org · SafeMoon" />
                </div>
                <button type="submit" disabled={!input.trim() || scanning} className="scan-btn">
                  {scanning ? <><Loader2 size={14} className="spin" />Analyzing…</> : <><Zap size={14} />Analyze</>}
                </button>
              </form>
              <div className="examples">
                <span>Try:</span>
                {[{ label: 'USDT contract', val: '0xdAC17F958D2ee523a2206206994597C13D831ec7' },{ label: 'uniswap.org', val: 'uniswap.org' },{ label: 'SafeMoon', val: 'SafeMoon' },{ label: 'Phishing site', val: 'metamask-verify.xyz' }].map(ex => (
                  <button key={ex.val} onClick={() => loadExample(ex.val)} className="example-chip">{ex.label}</button>
                ))}
              </div>
            </div>

            {scanning && !result && (
              <div className="loader-card"><Loader2 size={28} className="spin" color={C.primary} /><p>Running heuristic checks…</p></div>
            )}

            {result && !scanning && level && (
              <div className="results">
                <div className="score-card" style={{ borderColor: level.color + '55', background: `radial-gradient(circle at 20% 0%, ${level.color}18, transparent 60%), ${C.card}` }}>
                  <div className="score-row">
                    <div className="score-icon-wrap" style={{ backgroundColor: level.color + '22', borderColor: level.color + '55' }}>
                      <level.Icon size={30} color={level.color} />
                    </div>
                    <div>
                      <div className="score-label" style={{ color: level.color }}>{level.label}</div>
                      <div className="score-value">{result.score}<span className="score-max">/100</span></div>
                    </div>
                  </div>
                  <p>{level.msg}</p>
                  <div className="risk-bar"><div className="risk-fill" style={{ width: result.score + '%' }} /></div>
                  <div className="risk-labels"><span>SAFE</span><span>CAUTION</span><span>DANGER</span></div>
                </div>

                <div className="meta-card">
                  <div className="meta-icon" style={{ backgroundColor: typeStyle.color + '20', borderColor: typeStyle.color + '44' }}>
                    <typeStyle.Icon size={16} color={typeStyle.color} />
                  </div>
                  <div className="meta-body">
                    <span className="meta-type">{typeStyle.label}</span>
                    <code className="meta-value">{result.normalized}</code>
                    {result.chain && <span className="chain-badge">{result.chain === 'evm' ? 'EVM' : 'Solana'}</span>}
                  </div>
                  <button onClick={copyInput} className="copy-btn">{copied ? <><CheckCircle2 size={12} color={C.primary} />Copied</> : <><Copy size={12} />Copy</>}</button>
                </div>

                <div className="flag-summary">
                  {[
                    { l: 'Critical', v: flagCounts.critical || 0, ...FLAG_STYLE.critical },
                    { l: 'High',     v: flagCounts.high     || 0, ...FLAG_STYLE.high },
                    { l: 'Medium',   v: (flagCounts.medium || 0) + (flagCounts.low || 0), ...FLAG_STYLE.medium },
                    { l: 'Passed',   v: flagCounts.positive || 0, ...FLAG_STYLE.positive },
                  ].map((s, i) => (
                    <div key={i} className="flag-card">
                      <div className="flag-card-header">
                        <div className="flag-card-icon" style={{ backgroundColor: s.bg, borderColor: s.border }}>
                          <s.Icon size={13} color={s.color} />
                        </div>
                        <span className="flag-card-count">{s.v}</span>
                      </div>
                      <span className="flag-card-label">{s.l}</span>
                    </div>
                  ))}
                </div>

                <div className="findings-card">
                  <div className="findings-header">
                    <h3><Eye size={14} color={C.primary} />Detailed findings</h3>
                    <span>{result.flags.length} checks</span>
                  </div>
                  {result.flags.map((f, i) => {
                    const s = FLAG_STYLE[f.level];
                    return (
                      <div key={i} className="finding-row" style={{ borderBottom: i < result.flags.length - 1 ? `1px solid ${C.border}` : 'none' }}>
                        <div className="finding-icon" style={{ backgroundColor: s.bg, borderColor: s.border }}>
                          <s.Icon size={14} color={s.color} />
                        </div>
                        <div className="finding-body">
                          <div className="finding-title">
                            <span className="finding-badge" style={{ backgroundColor: s.bg, color: s.color, borderColor: s.border }}>{s.label}</span>
                            <strong>{f.title}</strong>
                          </div>
                          <p>{f.detail}</p>
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div className="disclaimer">
                  <Lock size={14} color={C.amber} />
                  <p><strong>Not financial advice.</strong> This tool runs static heuristic checks in your browser — it does not query live on-chain state, smart-contract source code, or WHOIS records. Always independently verify on <span style={{ color: C.primary }}>Etherscan / Solscan</span>, read the contract, and check community reputation before trading or connecting a wallet.</p>
                </div>
              </div>
            )}

            {!result && !scanning && (
              <div className="info-cards">
                {[
                  { icon: FileCode2, title: 'Contract addresses', desc: 'Paste any 0x… or Solana address to check format & vanity patterns.', color: C.primary },
                  { icon: Globe, title: 'Website URLs', desc: 'Detects typosquats, phishing keywords, and suspicious TLDs.', color: C.amber },
                  { icon: Coins, title: 'Token names', desc: 'Flags hype markers, rug-prone naming patterns, and impersonation.', color: C.danger },
                ].map((f, i) => (
                  <div key={i} className="info-card" style={{ borderColor: C.border }}>
                    <div className="info-card-icon" style={{ backgroundColor: f.color + '20', borderColor: f.color + '40' }}><f.icon size={16} color={f.color} /></div>
                    <strong>{f.title}</strong>
                    <p>{f.desc}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {view === 'history' && (
          <div className="history-view">
            <div className="history-stats">
              {[
                { l: 'Total scans',   v: stats.total,    Icon: TrendingUp, c: C.primary },
                { l: 'Critical',      v: stats.critical, Icon: ShieldX,    c: C.danger },
                { l: 'High risk',     v: stats.high,     Icon: ShieldAlert,c: C.danger },
                { l: 'Low risk',      v: stats.clean,    Icon: ShieldCheck,c: C.primary },
              ].map((s, i) => (
                <div key={i} className="stat-card">
                  <div className="stat-card-row">
                    <div className="stat-icon" style={{ backgroundColor: s.c + '20', borderColor: s.c + '40' }}><s.Icon size={13} color={s.c} /></div>
                    <span className="stat-count">{s.v}</span>
                  </div>
                  <span className="stat-label">{s.l}</span>
                </div>
              ))}
            </div>
            <div className="history-list">
              <div className="history-header"><h3><History size={14} color={C.primary} />Recent scans</h3><span>{history.length} entries</span></div>
              {history.length === 0 ? (
                <div className="empty-state"><History size={28} color={C.border} /><p>No scans yet — run your first analysis on the Scan tab.</p></div>
              ) : (
                history.map((h, i) => {
                  const lvl = LEVEL_STYLE[h.risk_level] || LEVEL_STYLE.Low;
                  const typ = TYPE_STYLE[h.input_type] || TYPE_STYLE.token;
                  return (
                    <div key={h.id} className="history-row" style={{ borderBottom: i < history.length - 1 ? `1px solid ${C.border}` : 'none' }}>
                      <div className="history-icon" style={{ backgroundColor: typ.color + '20', borderColor: typ.color + '40' }}><typ.Icon size={13} color={typ.color} /></div>
                      <div className="history-body">
                        <code>{h.query}</code>
                        <span>{new Date(h.scanned_at).toLocaleString()} · {h.flags_count ?? 0} findings</span>
                      </div>
                      <span className="history-level" style={{ backgroundColor: lvl.color + '18', color: lvl.color, borderColor: lvl.color + '40' }}>{h.risk_level}</span>
                      <span className="history-score" style={{ color: lvl.color }}>{h.risk_score ?? 0}</span>
                      <button onClick={() => { setInput(h.query); setResult(null); setView('scan'); }} className="rescan-btn"><ChevronRight size={11} /></button>
                      <button onClick={() => clearOne(h.id)} className="del-btn"><Trash2 size={12} /></button>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
