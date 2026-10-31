// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import "../src/LogAnchorLedger.sol";

interface Vm {
    function envBytes32(string calldata) external returns (bytes32);
    function envAddress(string calldata) external returns (address);
    function startBroadcast() external;
    function stopBroadcast() external;
}

contract DeployScript {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external returns (LogAnchorLedger ledger) {
        bytes32 streamId = vm.envBytes32("RAVEN_STREAM_ID");
        bytes32 genesisHash = vm.envBytes32("RAVEN_GENESIS_HASH");
        address anchor = vm.envAddress("RAVEN_ANCHOR_ADDRESS");
        vm.startBroadcast();
        ledger = new LogAnchorLedger();
        ledger.registerStream(streamId, genesisHash, anchor);
        vm.stopBroadcast();
    }
}
