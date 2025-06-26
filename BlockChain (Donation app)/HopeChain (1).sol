// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract HopeChain {
    address public admin; // Address of the contract administrator
    uint public totalDonations; // Total ETH donated to the contract

    // Struct to hold detailed donation info
    struct DonationInfo {
        address donor;
        uint amount;
        uint timestamp;
    }

    DonationInfo[] public donations; // Array to store all donation records
    mapping(address => uint) public donorBalances; // Maps each donor's address to the total amount they have donated.

    // Events
    event DonationReceived(address indexed donor, uint amount, uint timestamp);
    event FundsWithdrawn(address indexed admin, uint amount, uint timestamp);

    // Modifier to restrict admin-only functions
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action.");
        _;
    }

    // Set contract deployer as admin
    constructor() {
        admin = msg.sender;
    }

    // Function to accept donations
    function donate() public payable {
        require(msg.value > 0, "Donation must be greater than zero.");  
        require(msg.value >= 0.01 ether, "Minimum donation is 0.01 ETH.");

        // Update donor balance and total donations
        donorBalances[msg.sender] += msg.value;
        totalDonations += msg.value;

        // Store donation record in the array
        donations.push(DonationInfo({
            donor: msg.sender,
            amount: msg.value,
            timestamp: block.timestamp
        }));

        // Emit event
        emit DonationReceived(msg.sender, msg.value, block.timestamp);
    }

    // Return how much a specific address has donated
    function getDonationInfo(address donor) public view returns (uint) {
        return donorBalances[donor];
    }

    // Return total number of donation records
    function getDonationCount() public view returns (uint) {
        return donations.length;
    }

    // Return a specific donation record by index
    function getDonationByIndex(uint index) public view returns (address, uint, uint) {
        require(index < donations.length, "Index out of range");
        DonationInfo memory d = donations[index];
        return (d.donor, d.amount, d.timestamp);
    }
        
    // Allow only the admin to withdraw all funds
    function withdrawFunds() public onlyAdmin {
        uint balance = address(this).balance;
        require(balance > 0, "No funds available for withdrawal.");
        payable(admin).transfer(balance);
        emit FundsWithdrawn(admin, balance, block.timestamp);
    }

    
}
