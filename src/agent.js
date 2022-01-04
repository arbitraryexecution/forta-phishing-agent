const {
  getEthersBatchProvider, Finding, FindingSeverity, FindingType, ethers,
} = require('forta-agent');

const provider = getEthersBatchProvider();

const APPROVAL_EVENT_SIGNATURE = 'event Approval(address indexed owner, address indexed spender, uint256 value)';

// keep track of addresses that are likely centralized exchanges to skip their transactions when they occur
let blacklist = [];

// track EOAs across transactions and blocks, accumulating a count over time
const suspiciousApprovals = {};

// set a threshold for how many transactions to any EOA should be flagged as anomalous
const approvalThreshold = 10;

// set a transaction count threshold high enough to filter out likely centralized exchange EOAs
const nonceThreshold = 200;

/*
const handleTransaction = async (txEvent) => {

  // initialize the array that will hold the findings for this transaction
  const findings = [];

  // find any token approvals in the transaction
  const approvalLogs = txEvent.filterLog([APPROVAL_EVENT_SIGNATURE]);

  const promises = approvalLogs.map(async (log) => {

    const { args: { owner, spender } } = log;

    // check the blacklist for the addresses that are likely centralized exchanges
    if (blacklist.indexOf(spender) !== -1) {
      return {};
    }

    // check that the spender address is not the black hole
    if (spender === ethers.constants.AddressZero) {
      return {};
    }

    // check that the owner address corresponds to an EOA
    const ownerCode = await provider.getCode(owner);
    if (ownerCode !== '0x') {
      return {};
    }

    // check that the spender address corresponds to an EOA
    const spenderCode = await provider.getCode(spender);
    if (spenderCode !== '0x') {
      return {};
    }

    // check the number of transactions that the spender address has performed
    if (!suspiciousApprovals[spender]) {
      const nonce = await provider.getTransactionCount(spender, txEvent.blockNumber);
      if (nonce >= nonceThreshold) {
        // if the address has performed more transactions than the threshold, add the address to the blacklist
        // as a likely centralized exchange EOA
        blacklist.push(spender);
        return {};
      }
    }

    // the approval was from an EOA to an EOA, therefore return the result
    return {
      spender, owner, tokenAddress: log.address, blockNumber: txEvent.blockNumber,
    };
  });

  // wait for the promises to settle
  let results = await Promise.all(promises);
  results = results.filter((result) => result.spender !== undefined);

  // remove duplicate entries from the blacklist
  blacklist = [...new Set(blacklist)];

  // place results into global variable to track approvals
  results.forEach((result) => {
    const {
      spender, owner, tokenAddress, blockNumber,
    } = result;
    if (!suspiciousApprovals[spender]) {
      suspiciousApprovals[spender] = [];
    }
    suspiciousApprovals[spender].push({
      owner, tokenAddress, blockNumber,
    });
  });

  // check the accumulated history of approvals
  Object.entries(suspiciousApprovals).forEach(([spender, approvals]) => {
    if (approvals.length > approvalThreshold) {
      // create finding
      findings.push(
        Finding.fromObject({
          name: 'Suspicious Approvals',
          description: `${approvals.length} approval events detected to EOA ${spender}`,
          alertId: 'AE-SUSPICIOUS-APPROVALS',
          severity: FindingSeverity.Medium,
          type: FindingType.Suspicious,
        }),
      );
    }
  });

  return findings;
};
*/

const iface = new ethers.utils.Interface([APPROVAL_EVENT_SIGNATURE]);

let blockFetchStart = 13650638;
const blockStop = 13652300;
let offset = 30;
let running = false;

const handleBlock = async (blockEvent) => {
  const findings = [];

  if (blockFetchStart + offset > blockStop) {
    offset = blockStop - blockFetchStart;
  }

  if (offset === 0) {
    process.exit(1);
  }

  if (running) {
    return findings;
  }

  let logList = [];
  let logTemp;

  if (!running) {
    running = true;
    while (offset !== 0) {

      // get all of the logs corresponding to the Approval signature
      console.log(`Getting blocks ${blockFetchStart} to ${blockFetchStart + offset}`);
      logTemp = await provider.getLogs({
        fromBlock: blockFetchStart,
        toBlock: blockFetchStart + offset,
        topics: ['0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925'],
      });

      logList.push(...logTemp);

      blockFetchStart += offset;

      if (blockFetchStart + offset > blockStop) {
        offset = blockStop - blockFetchStart;
      }
    }
  }

  let promises;

  offset = 0;
  let count = 2000;
  console.log('Number of logs to process: ', logList.length);
  while (true) {
    logTemp = logList.slice(offset, offset + count);
    console.log('Working on offset: ', offset, ', count: ', count);

    promises = logTemp.map(async (log) => {
      const { data, topics } = log;

      // filter out events that have the same keccak256 hash but are not actual matches
      if ((topics.length !== 3) || (data === '0x')) {
        return {};
      }

      const { args: { owner, spender } } = iface.parseLog({ data, topics });

      // check the blacklist for the address
      if (blacklist.indexOf(spender) !== -1) {
        return {};
      }

      // check that the spender address is not the black hole
      if (spender === ethers.constants.AddressZero) {
        return {};
      }

      // check that the owner address corresponds to an EOA
      const ownerCode = await provider.getCode(owner);
      if (ownerCode !== '0x') {
        return {};
      }

      // check that the spender address corresponds to an EOA
      const spenderCode = await provider.getCode(spender);
      if (spenderCode !== '0x') {
        return {};
      }

      // check the number of transactions that the spender address has performed
      if (!suspiciousApprovals[spender]) {
        // console.log('Spender not in suspiciousApprovals Object, checking nonce');
        const nonce = await provider.getTransactionCount(spender, blockEvent.blockNumber);
        // console.log('spender: ', spender, ',nonce: ', nonce);
        if (nonce >= nonceThreshold) {
          // console.log('Nonce over threshold, adding spender to blacklist: ', spender);
          blacklist.push(spender);
          return {};
        }
      }

      return {
        spender, owner, tokenAddress: log.address, blockNumber: blockEvent.blockNumber,
      };
    });

    // wait for the promises to settle
    let results = await Promise.all(promises);
    results = results.filter((result) => result.spender !== undefined);

    // place results into global variable to track approvals
    results.forEach((result) => {
      const {
        spender, owner, tokenAddress, blockNumber,
      } = result;
      if (!suspiciousApprovals[spender]) {
        suspiciousApprovals[spender] = [];
      }
      suspiciousApprovals[spender].push({
        owner, tokenAddress, blockNumber,
      });
    });

    // remove duplicate entries from the blacklist
    blacklist = [...new Set(blacklist)];

    offset += count;
    if (offset === logList.length) {
      break;
    }

    if (logList.length - offset < count) {
      count = logList.length - offset;
    }
  }

  // check the accumulated history of approvals
  Object.entries(suspiciousApprovals).forEach(([spender, approvals]) => {
    // console.log('Spender: ', spender, ', Number of approvals: ', approvals.length);
    if (approvals.length > approvalThreshold) {
      const owners = approvals.map(entry => entry.owner).join();
      const tokens = approvals.map(entry => entry.tokenAddress).join();

      // create finding
      findings.push(
        Finding.fromObject({
          name: 'Suspicious Approvals',
          description: `${approvals.length} approval events detected to EOA ${spender}`,
          alertId: 'AE-SUSPICIOUS-APPROVALS',
          severity: FindingSeverity.Medium,
          type: FindingType.Suspicious,
          metadata: {
            owners,
            tokens,
          }
        }),
      );
    }
  });

  return findings;
}

module.exports = {
  // handleTransaction,
  handleBlock,
};
