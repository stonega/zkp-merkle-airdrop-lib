"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TreeNode = exports.MerkleTree = void 0;
const Library_1 = require("./Library");
/** Merkle tree of MimcSponge hashes */
class MerkleTree {
    constructor(linkedRoot, linkedLeaves) {
        this.root = linkedRoot;
        this.leaves = linkedLeaves;
    }
    /**
     * For a set of leaves recursively computes hashes of adjacent nodes upwards until reaching a root.
     * Note: Significantly slower than `MerkleTree.createFromStorageString` as it rehashes the whole tree.
     */
    static createFromLeaves(leaves) {
        let leafNodes = leaves.map(leaf => new TreeNode(leaf));
        let rootNode = MerkleTree.hashChildrenAndLinkToParent(leafNodes)[0];
        return new MerkleTree(rootNode, leafNodes);
    }
    static hashChildrenAndLinkToParent(levelLeaves) {
        if (levelLeaves.length == 1)
            return levelLeaves;
        let parents = [];
        for (let i = 0; i < levelLeaves.length; i += 2) {
            let l = levelLeaves[i];
            let r = levelLeaves[i + 1];
            let hash = (0, Library_1.mimcSponge)(l.val, r.val);
            let parent = new TreeNode(hash, l, r);
            parents.push(parent);
            l.parent = parent;
            r.parent = parent;
        }
        return this.hashChildrenAndLinkToParent(parents);
    }
    /**
     *
     *  For ("A\nB,C\nD,E,F,G"), return the MerkleTree boject(A).
     *
     *          A
     *        /   \
     *       B     C
     *      / \   / \
     *     D   E F   G
     *
     */
    static createFromStorageString(ss) {
        let lines = ss.split("\n");
        let rootNode = new TreeNode(BigInt(lines[0]));
        let currRow = [rootNode];
        for (let lineIndex = 1; lineIndex < lines.length; lineIndex++) {
            let vals = lines[lineIndex].split(",");
            if (vals.length / 2 != currRow.length)
                throw new Error("Malformatted tree.");
            for (let rowIndex = 0; rowIndex < currRow.length; rowIndex++) {
                let parent = currRow[rowIndex];
                let lChild = new TreeNode(BigInt(vals[2 * rowIndex]), undefined, undefined, parent);
                let rChild = new TreeNode(BigInt(vals[2 * rowIndex + 1]), undefined, undefined, parent);
                parent.lChild = lChild;
                parent.rChild = rChild;
            }
            currRow = MerkleTree.getChildRow(currRow);
        }
        return new MerkleTree(rootNode, currRow);
    }
    /**
     * Computes the MerkleProof for a given leafVal in the tree.
     */
    getMerkleProof(leafVal) {
        var leaf = this.findMatchingLeaf(leafVal);
        let merkleProof = {
            vals: new Array(),
            indices: new Array()
        };
        while (leaf.val != this.root.val) {
            if (leaf.parent.lChild.val == leaf.val) { // Right child
                merkleProof.vals.push(leaf.parent.rChild.val);
                merkleProof.indices.push(0);
            }
            else if (leaf.parent.rChild.val == leaf.val) { // Left child
                merkleProof.vals.push(leaf.parent.lChild.val);
                merkleProof.indices.push(1);
            }
            else {
                throw new Error("This shouldn't have happened.");
            }
            leaf = leaf.parent;
        }
        return merkleProof;
    }
    /**
     *          A
     *        /   \
     *       B     C
     *      / \   / \
     *     D   E F   G
     *
     *  For tree above we create "A\nB,C\nD,E,F,G".
     */
    getStorageString() {
        let result = "";
        let currRow = [this.root];
        while (currRow.length > 0) {
            for (let i = 0; i < currRow.length; i++) {
                result += (0, Library_1.toHex)(currRow[i].val);
                if (i != currRow.length - 1)
                    result += ",";
            }
            currRow = MerkleTree.getChildRow(currRow);
            if (currRow.length != 0)
                result += "\n";
        }
        return result;
    }
    leafExists(search) {
        return this.leaves.find(node => node.val == search) !== undefined;
    }
    /**
     *          A
     *        /   \
     *       B     C
     *      / \   / \
     *     D   E F   G
     *
     *  getChildRow([B,C]) -> [D,E,F,G]
     */
    static getChildRow(parentLevel) {
        let children = [];
        for (let parent of parentLevel) {
            if (parent.lChild && parent.rChild) {
                children.push(parent.lChild);
                children.push(parent.rChild);
            }
        }
        return children;
    }
    findMatchingLeaf(leafVal) {
        let matchingLeaf = this.leaves.find(leaf => leaf.val == leafVal);
        if (matchingLeaf == undefined) {
            throw new Error("Failed to find leaf.");
        }
        return matchingLeaf;
    }
}
exports.MerkleTree = MerkleTree;
class TreeNode {
    constructor(val, lChild, rChild, parent) {
        this.val = val;
        this.lChild = lChild;
        this.rChild = rChild;
        this.parent = parent;
    }
}
exports.TreeNode = TreeNode;
