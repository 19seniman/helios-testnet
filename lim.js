import blessed from "blessed";
import chalk from "chalk";
import figlet from "figlet";
import { ethers } from "ethers";
import fs from "fs";
import { HttpsProxyAgent } from "https-proxy-agent";
import { SocksProxyAgent } from "socks-proxy-agent";
import axios from "axios";
import { v4 as uuidv4 } from "uuid";

const RPC_URL = "https://testnet1.helioschainlabs.org/";
const CONFIG_FILE = "config.json";
const TOKEN_ADDRESS = "0xD4949664cD82660AaE99bEdc034a0deA8A0bd517";
const BRIDGE_ROUTER_ADDRESS = "0x0000000000000000000000000000000000000900";
const STAKE_ROUTER_ADDRESS = "0x0000000000000000000000000000000000000800";
const CHAIN_ID = 42000;
const availableChains = [11155111, 43113, 97, 80002];
const chainNames = {
  11155111: "Sepolia",
  43113: "Fuji",
  97: "BSC Testnet",
  80002: "Amoy"
};

const availableValidators = [
  { name: "helios-hedge", address: "0x007a1123a54cdd9ba35ad2012db086b9d8350a5f" },
  { name: "helios-supra", address: "0x882f8a95409c127f0de7ba83b4dfa0096c3d8d79" }
];

const isDebug = false;

let walletInfo = {
  address: "N/A",
  balanceHLS: "0.0000",
  activeAccount: "N/A"
};
let transactionLogs = [];
let activityRunning = false;
let isCycleRunning = false;
let shouldStop = false;
let dailyActivityInterval = null;
let privateKeys = [];
let proxies = [];
let selectedWalletIndex = 0;
let loadingSpinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const borderBlinkColors = ["cyan", "blue", "magenta", "red", "yellow", "green"];
let borderBlinkIndex = 0;
let blinkCounter = 0;
let spinnerIndex = 0;
let nonceTracker = {};
let hasLoggedSleepInterrupt = false;
let isHeaderRendered = false;
let activeProcesses = 0;

let dailyActivityConfig = {
  bridgeRepetitions: 1,
  minHlsBridge: 0.001,
  maxHlsBridge: 0.004,
  stakeRepetitions: 1,
  minHlsStake: 0.01,
  maxHlsStake: 0.03
};

function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const data = fs.readFileSync(CONFIG_FILE, "utf8");
      const config = JSON.parse(data);
      dailyActivityConfig.bridgeRepetitions = Number(config.bridgeRepetitions) || 1;
      dailyActivityConfig.minHlsBridge = Number(config.minHlsBridge) || 0.001;
      dailyActivityConfig.maxHlsBridge = Number(config.maxHlsBridge) || 0.004;
      dailyActivityConfig.stakeRepetitions = Number(config.stakeRepetitions) || 1;
      dailyActivityConfig.minHlsStake = Number(config.minHlsStake) || 0.01;
      dailyActivityConfig.maxHlsStake = Number(config.maxHlsStake) || 0.03;
    } else {
      addLog("No config file found, using default settings.", "info");
    }
  } catch (error) {
    addLog(`Failed to load config: ${error.message}`, "error");
  }
}

function saveConfig() {
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(dailyActivityConfig, null, 2));
    addLog("Configuration saved successfully.", "success");
  } catch (error) {
    addLog(`Failed to save config: ${error.message}`, "error");
  }
}

async function makeJsonRpcCall(method, params) {
  try {
    const id = uuidv4();
    const proxyUrl = proxies.length > 0 ? proxies[selectedWalletIndex % proxies.length] : null; 
    const agent = createAgent(proxyUrl);
    const response = await axios.post(RPC_URL, {
      jsonrpc: "2.0",
      id,
      method,
      params
    }, {
      headers: { "Content-Type": "application/json" },
      httpsAgent: agent 
    });
    const data = response.data;
    if (data.error) {
      throw new Error(`RPC Error: ${data.error.message} (code: ${data.error.code})`);
    }
    if (!data.hasOwnProperty('result')) {
      throw new Error("No result in RPC response");
    }
    return data.result;
  } catch (error) {
    const errorMessage = error.response
      ? `HTTP ${error.response.status}: ${error.message}`
      : error.message;
    addLog(`JSON-RPC call failed (${method}): ${errorMessage}`, "error");
    throw error;
  }
}

process.on("unhandledRejection", (reason, promise) => {
  addLog(`Unhandled Rejection at: ${promise}, reason: ${reason.message || reason}`, "error");
});

process.on("uncaughtException", (error) => {
  addLog(`Uncaught Exception: ${error.message}\n${error.stack}`, "error");
  process.exit(1);
});

function getShortAddress(address) {
  return address ? address.slice(0, 6) + "..." + address.slice(-4) : "N/A";
}

function addLog(message, type = "info") {
  if (type === "debug" && !isDebug) return;
  const timestamp = new Date().toLocaleTimeString("id-ID", { timeZone: "Asia/Jakarta" });
  let coloredMessage;
  switch (type) {
    case "error":
      coloredMessage = chalk.redBright(message);
      break;
    case "success":
      coloredMessage = chalk.greenBright(message);
      break;
    case "wait":
      coloredMessage = chalk.yellowBright(message);
      break;
    case "info":
      coloredMessage = chalk.whiteBright(message);
      break;
    case "delay":
      coloredMessage = chalk.cyanBright(message);
      break;
    case "debug":
      coloredMessage = chalk.blueBright(message);
      break;
    default:
      coloredMessage = chalk.white(message);
  }
  const logMessage = `[${timestamp}] ${coloredMessage}`;
  transactionLogs.push(logMessage);
  updateLogs();
}

function getShortHash(hash) {
  return hash.slice(0, 6) + "..." + hash.slice(-4);
}

function clearTransactionLogs() {
  transactionLogs = [];
  if (logBox) {
    logBox.setContent('');
    logBox.scrollTo(0);
  }
  addLog("Transaction logs cleared.", "success");
}

function loadPrivateKeys() {
  try {
    const data = fs.readFileSync("pk.txt", "utf8");
    privateKeys = data.split("\n").map(key => key.trim()).filter(key => key.match(/^(0x)?[0-9a-fA-F]{64}$/));
    if (privateKeys.length === 0) throw new Error("No valid private keys in pk.txt");
    addLog(`Loaded ${privateKeys.length} private keys from pk.txt`, "success");
  } catch (error) {
    addLog(`Failed to load private keys: ${error.message}`, "error");
    privateKeys = [];
  }
}

function loadProxies() {
  try {
    if (fs.existsSync("proxy.txt")) {
      const data = fs.readFileSync("proxy.txt", "utf8");
      proxies = data.split("\n").map(proxy => proxy.trim()).filter(proxy => proxy);
      if (proxies.length === 0) throw new Error("No proxy found in proxy.txt");
      addLog(`Loaded ${proxies.length} proxies from proxy.txt`, "success");
    } else {
      addLog("No proxy.txt found, running without proxy.", "info");
      proxies = [];
    }
  } catch (error) {
    addLog(`Failed to load proxies: ${error.message}`, "info");
    proxies = [];
  }
}

function createAgent(proxyUrl) {
  if (!proxyUrl) return null;
  if (proxyUrl.startsWith("socks")) {
    return new SocksProxyAgent(proxyUrl);
  } else {
    return new HttpsProxyAgent(proxyUrl);
  }
}

async function getProviderWithProxy(proxyUrl, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const agent = createAgent(proxyUrl);
      const provider = new ethers.JsonRpcProvider(RPC_URL, { chainId: CHAIN_ID, name: "Helios" }, { fetch: fetch, agent });
      const network = await provider.getNetwork();
      if (Number(network.chainId) !== CHAIN_ID) {
        throw new Error(`Network chain ID mismatch: expected ${CHAIN_ID}, got ${network.chainId}`);
      }
      return provider;
    } catch (error) {
      addLog(`Attempt ${attempt}/${maxRetries} failed to initialize provider: ${error.message}`, "error");
      if (attempt < maxRetries) await sleep(1000);
    }
  }
  try {
    addLog(`Proxy failed, falling back to direct connection`, "warn");
    const provider = new ethers.JsonRpcProvider(RPC_URL, { chainId: CHAIN_ID, name: "Helios" });
    const network = await provider.getNetwork();
    if (Number(network.chainId) !== CHAIN_ID) {
      throw new Error(`Network chain ID mismatch: expected ${CHAIN_ID}, got ${network.chainId}`);
    }
    return provider;
  } catch (error) {
    addLog(`Fallback failed: ${error.message}`, "error");
    throw error;
  }
}

async function sleep(ms) {
  if (shouldStop) {
    if (!hasLoggedSleepInterrupt) {
      addLog("Process stopped successfully.", "info");
      hasLoggedSleepInterrupt = true;
    }
    return;
  }
  activeProcesses++;
  try {
    await new Promise((resolve) => {
      const timeout = setTimeout(() => {
        resolve();
      }, ms);
      const checkStop = setInterval(() => {
        if (shouldStop) {
          clearTimeout(timeout);
          clearInterval(checkStop);
          if (!hasLoggedSleepInterrupt) {
            addLog("Process interrupted.", "info");
            hasLoggedSleepInterrupt = true;
          }
          resolve();
        }
      }, 100);
    });
  } catch (error) {
    addLog(`Sleep error: ${error.message}`, "error");
  } finally {
    activeProcesses = Math.max(0, activeProcesses - 1);
  }
}

async function updateWalletData() {
  const tokenAbi = ["function balanceOf(address) view returns (uint256)"];
  const walletDataPromises = privateKeys.map(async (privateKey, i) => {
    try {
      const proxyUrl = proxies.length > 0 ? proxies[i % proxies.length] : null;
      const provider = await getProviderWithProxy(proxyUrl);
      const wallet = new ethers.Wallet(privateKey, provider);
      
      const tokenContract = new ethers.Contract(TOKEN_ADDRESS, tokenAbi, provider);
      const hlsBalance = await tokenContract.balanceOf(wallet.address);
      
      const formattedHLS = Number(ethers.formatUnits(hlsBalance, 18)).toFixed(4);
      
      const formattedEntry = `${i === selectedWalletIndex ? "→ " : "  "}${chalk.bold.magentaBright(getShortAddress(wallet.address))}              ${chalk.bold.cyanBright(formattedHLS.padEnd(8))}`;
      
      if (i === selectedWalletIndex) {
        walletInfo.address = wallet.address;
        walletInfo.activeAccount = `Account ${i + 1}`;
        walletInfo.balanceHLS = formattedHLS;
      }
      return formattedEntry;
    } catch (error) {
      addLog(`Failed to fetch wallet data for account #${i + 1}: ${error.message}`, "error");
      return `${i === selectedWalletIndex ? "→ " : "  "}N/A 0.0000`;
    }
  });
  try {
    const walletData = await Promise.all(walletDataPromises);
    addLog("Wallet data updated.", "success");
    return walletData;
  } catch (error) {
    addLog(`Wallet data update failed: ${error.message}`, "error");
    return [];
  }
}

async function getNextNonce(provider, walletAddress) {
  if (shouldStop) {
    addLog("Nonce fetch stopped due to stop request.", "info");
    throw new Error("Process stopped");
  }
  if (!walletAddress || !ethers.isAddress(walletAddress)) {
    addLog(`Invalid wallet address: ${walletAddress}`, "error");
    throw new Error("Invalid wallet address");
  }
  try {
    const pendingNonce = await provider.getTransactionCount(walletAddress, "pending");
    const lastUsedNonce = nonceTracker[walletAddress] ?? (pendingNonce - 1);
    const nextNonce = Math.max(pendingNonce, lastUsedNonce + 1);
    nonceTracker[walletAddress] = nextNonce;
    addLog(`Debug: Fetched nonce ${nextNonce} for ${getShortAddress(walletAddress)}`, "debug");
    return nextNonce;
  } catch (error) {
    addLog(`Failed to fetch nonce for ${getShortAddress(walletAddress)}: ${error.message}`, "error");
    throw error;
  }
}

async function bridge(wallet, amount, recipient, destChainId) {
  try {
    if (!wallet.address || !ethers.isAddress(wallet.address)) {
      throw new Error(`Invalid wallet address: ${wallet.address}`);
    }
    addLog(`Debug: Building bridge transaction for amount ${amount} HLS to ${getShortAddress(wallet.address)}`, "debug");
    const chainIdHex = ethers.toBeHex(destChainId).slice(2).padStart(64, '0');
    const offset = "00000000000000000000000000000000000000000000000000000000000000a0";
    const token = TOKEN_ADDRESS.toLowerCase().slice(2).padStart(64, '0');
    addLog(`Debug: Converting amount ${amount} to wei`, "debug");
    const amountWei = ethers.parseUnits(amount.toString(), 18);
    addLog(`Debug: amountWei: ${amountWei.toString()}`, "debug");
    
    let amountHexRaw;
    try {
      amountHexRaw = ethers.toBeHex(amountWei);
      addLog(`Debug: amountHexRaw: ${amountHexRaw}`, "debug");
    } catch (error) {
      addLog(`Debug: Failed to convert amountWei to hex: ${error.message}`, "error");
      throw new Error(`Hex conversion failed: ${error.message}`);
    }
    
    let amountHex;
    try {
      amountHex = ethers.zeroPadValue(amountHexRaw, 32).slice(2);
      addLog(`Debug: amountHex padded: ${amountHex}`, "debug");
    } catch (error) {
      addLog(`Debug: Failed to pad amountHex: ${error.message}`, "error");
      throw new Error(`Hex padding failed: ${error.message}`);
    }
    
    const gasParam = ethers.toBeHex(ethers.parseUnits("1", "gwei")).slice(2).padStart(64, '0');
    addLog(`Debug: Encoding recipient ${recipient} as string`, "debug");
    const recipientString = `0x${recipient.toLowerCase().slice(2)}`;
    const recipientLength = ethers.toBeHex(recipientString.length).slice(2).padStart(64, '0');
    const recipientPadded = Buffer.from(recipientString).toString('hex').padEnd(64, '0');
    
    const inputData = "0x7ae4a8ff" + 
      chainIdHex + 
      offset + 
      token + 
      amountHex + 
      gasParam + 
      recipientLength + 
      recipientPadded;
    addLog(`Debug: inputData: ${inputData}`, "debug");

    const tokenAbi = [
      "function allowance(address,address) view returns (uint256)",
      "function approve(address,uint256) returns (bool)"
    ];
    const tokenContract = new ethers.Contract(TOKEN_ADDRESS, tokenAbi, wallet);
    const allowance = await tokenContract.allowance(wallet.address, BRIDGE_ROUTER_ADDRESS);
    addLog(`Debug: Allowance: ${allowance.toString()}`, "debug");
    if (allowance < amountWei) {
      addLog(`Approving router to spend ${amount} HLS`, "info");
      const approveTx = await tokenContract.approve(BRIDGE_ROUTER_ADDRESS, amountWei);
      await approveTx.wait();
      addLog("Approval successful", "success");
    }

    const tx = {
      to: BRIDGE_ROUTER_ADDRESS,
      data: inputData,
      gasLimit: 1500000,
      chainId: CHAIN_ID,
      nonce: await getNextNonce(wallet.provider, wallet.address)
    };
    addLog(`Debug: Transaction object: ${JSON.stringify(tx)}`, "debug");
    
    const sentTx = await wallet.sendTransaction(tx);
    addLog(`Bridge transaction sent: ${getShortHash(sentTx.hash)}`, "success");
    const receipt = await sentTx.wait();
    
    if (receipt.status === 0) {
      addLog(`Bridge transaction reverted: ${JSON.stringify(receipt)}`, "error");
      throw new Error("Transaction reverted");
    }
    
    try {
      await makeJsonRpcCall("eth_getHyperionAccountTransferTxsByPageAndSize", [
        wallet.address,
        "0x1",
        "0xa"
      ]);
    } catch (rpcError) {
      addLog(`Failed to sync with portal via JSON-RPC: ${rpcError.message}`, "error");
    }
    
    addLog("Bridge Transaction Confirmed And Synced With Portal", "success");
  } catch (error) {
    addLog(`Bridge operation failed: ${error.message}`, "error");
    if (error.reason) {
      addLog(`Revert reason: ${error.reason}`, "error");
    }
    if (error.receipt) {
      addLog(`Transaction receipt: ${JSON.stringify(error.receipt)}`, "debug");
    }
    throw error;
  }
}

async function stake(wallet, amount, validatorAddress, validatorName) {
  try {
    if (!wallet.address || !ethers.isAddress(wallet.address)) {
      throw new Error
