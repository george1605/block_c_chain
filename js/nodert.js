const CryptoJS = require('crypto-js');

// block structure - this is the prototype
let Block = {
    header: {
        version: 1,
        nonce: 0,
        prev_sha: '',
        merkle: '',
        timestamp: new Date(),
        difficulty: 1
    },

    body: {
        sha: '',
        transactions: []
    }
};

class Transaction
{
    constructor(from, to, amount)
    {
        this.from = from;
        this.to = to;
        this.amount = amount;
    }

    validate()
    {
        // send it to the network I guess
    }
}

function mineBlock(block, max_sha) {
    let headerString = JSON.stringify(block.header);
    let last_hash = CryptoJS.SHA256(headerString).toString();
    
    while (last_hash >= max_sha) {  // Fix condition for correct comparison
        block.header.nonce++;
        headerString = JSON.stringify(block.header); // Update header string after changing nonce
        last_hash = CryptoJS.SHA256(headerString).toString();
    }

    block.body.sha = last_hash;
}

function createBlock() {
    let b = Object.create(Block);
    b.header.timestamp = new Date();
    b.header.difficulty = Math.floor(Math.random() * (1 << 31)); // a random difficulty
    return b;
}

function addTransaction(block, transaction) {
    if(!transaction.validate())
        return null;
    block.body.transactions.push(transaction);
}

// Example usage:
let block = createBlock();
mineBlock(block, '00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'); // Example max_sha

console.log(block.body.sha);
