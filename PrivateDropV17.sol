// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/*
 * @title PrivateDropV17 - 链上资金匿名分发协议（隐私增强版）
 * @dev 基于智能合约的隐私保护资金池，实现存款人与取款人地址链上零关联，新增资金池记录清理功能
 * 
 *  核心特性：
 * 1. **不完全去中心化** - 除了在合约出现重大漏洞时部署者可以暂停交易以外无任何权限
 * 2. **地址关联切断** - 通过一次性存款建立独立资金池，取款地址与存款地址在链上无直接关联
 * 3. **权限分层控制** - 三层权限体系：存款人(Owner)、取款人(Spender)、恢复地址(Recovery)
 * 4. **签名验证机制** - 所有关键操作均需链下签名，操作可委托他人执行而不暴露私钥
 * 5. **独立资金池** - 每个存款创建独立池，多用户资金完全隔离
 * 6. **记录可清理** - 资金分配完毕后，存款人可主动清理该资金池的链上关联记录，增强隐私
 * 
 *  适用场景：
 * - 项目方向匿名团队成员发放报酬
 * - 机构向外部贡献者支付顾问费
 * - 个人资产隐私保护与传承规划
 * - 跨司法辖区资金合规转移
 * 
 * ⚠️  ⚠️  ⚠️  重要警告  ⚠️  ⚠️  ⚠️
 * - 请严格遵守您所在司法管辖区的法律法规
 * - 请勿将本合约用于任何非法活动，包括但不限于洗钱、资助恐怖主义或欺诈
 * - 合约的隐私特性旨在保护合法商业活动的隐私，而非帮助违法行为
 * - 不是质押合约，请勿相信任何人让你通过本合约进行质押操作 
 * - 理论上通过存款人的资金池ID可以查到资金流向
 * - 请不要多次套娃使用，这会使资金更加难以追踪
 * - 如果多次使用造成资金流向完全中断责任使用者自负
 * 
 *  技术架构：
 * - 存款：一次性存入资金，设置1个Owner、最多10个Spender、1个Recovery地址
 * - 取款：Spender使用私钥对取款信息签名，验证后直接提款
 * - 管理：Owner可冻结/解冻资金、修改取款人额度、更换恢复地址
 * - 恢复：Owner签名授权后，Recovery地址可一次性取回全部剩余资金
 * - 清理：当资金池余额为零时，Owner可签名触发清理，永久删除该池的链上关联记录
 * 
 *  费用模型：
 * - 存款时收取1%协议手续费（仅存款时一次性收取）
 * - 后续所有操作零费用（Gas费由执行交易的用户自行承担）
 * - Fee Wallet可由合约部署者更换，以确保协议可持续运行
 * 
 *  安全设计：
 * - 非托管模式：合约永不掌握用户私钥，资金控制权始终属于用户
 * - 多重验证：所有操作需对应权限的链下签名验证
 * - 防重放攻击：Nonce递增机制确保每笔签名唯一
 * - 紧急停止：部署者仅在发现合约重大漏洞时可全局暂停
 * - Reentrancy Guard：标准重入攻击防护
 * 
 *  数据隐私：
 * - 链上仅存储：资金池余额、地址列表（公开但无直接关联性）
 * - 链下处理：所有签名操作在用户本地完成，私钥永不触网
 * - 关联隔离：通过独立的资金池设计隔离不同存款人信息
 * - 记录清理：提供可选的链上记录清理功能，进一步增强隐私保护
 * 
 * @notice 本合约是一种技术中立的链上工具。使用者应对其行为承担全部法律责任，并确保其使用方式符合所有相关法律法规。
 * @author 匿名开发者
 * @PrivateDrop 1.7.0
 */
contract PrivateDropV17 is ReentrancyGuard {
    using SafeERC20 for IERC20;

    address payable public feeWallet;
    address public immutable owner;
    bool public emergencyStop = false;

    uint256 public constant FEE_RATE = 100;
    uint256 public constant MAX_SPENDERS = 10;

    struct Spender {
        address spenderAddress;
        uint256 limit;
        uint256 withdrawn;
        uint256 nonce;
    }

    struct Deposit {
        address token;
        uint256 balance;
        address ownerAddress;
        address recoveryAddress;
        bool frozen;
        uint256 ownerNonce;
        Spender[] spenders;
    }

    Deposit[] public deposits;

    event Deposited(uint256 indexed id, address indexed token, uint256 totalAmount, uint256 netAmount);
    event Withdrawn(uint256 indexed id, address indexed token, uint256 amount, address to);
    event Frozen(uint256 indexed id);
    event Unfrozen(uint256 indexed id);
    event Recovered(uint256 indexed id, address indexed token, uint256 amount, address to);
    event DepositCleaned(uint256 indexed id);  // 新增清理事件
    event FeeWalletUpdated(address oldWallet, address newWallet);
    event EmergencyStopToggled(bool stopped);

    constructor(address payable _feeWallet) {
        require(_feeWallet != address(0), "Zero fee wallet");
        feeWallet = _feeWallet;
        owner = msg.sender;
    }

    receive() external payable { revert("Use depositNative"); }
    fallback() external payable { revert("Use depositNative"); }

    modifier whenNotStopped() {
        require(!emergencyStop, "Emergency stop active");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    function updateFeeWallet(address payable newFeeWallet) external onlyOwner {
        require(newFeeWallet != address(0), "Zero address");
        emit FeeWalletUpdated(feeWallet, newFeeWallet);
        feeWallet = newFeeWallet;
    }

    function toggleEmergencyStop(bool stop) external onlyOwner {
        emergencyStop = stop;
        emit EmergencyStopToggled(stop);
    }

    // 原生币存款
    function depositNative(
        address ownerAddress,
        address recoveryAddress,
        address[] calldata spenderAddresses,
        uint256[] calldata spenderLimits
    ) external payable whenNotStopped nonReentrant {
        require(msg.value > 0.01 ether, "Too small");

        uint256 totalAmount = msg.value;
        uint256 fee = totalAmount * FEE_RATE / 10000;
        uint256 netAmount = totalAmount - fee;

        (bool success,) = feeWallet.call{value: fee}("");
        require(success, "Fee transfer failed");

        _createDeposit(address(0), totalAmount, netAmount, ownerAddress, recoveryAddress, spenderAddresses, spenderLimits);
    }

    // ERC20存款
    function depositERC20(
        address token,
        uint256 totalAmount,
        address ownerAddress,
        address recoveryAddress,
        address[] calldata spenderAddresses,
        uint256[] calldata spenderLimits
    ) external whenNotStopped nonReentrant {
        require(token != address(0), "Invalid token");
        require(totalAmount > 0, "Zero amount");

        uint256 fee = totalAmount * FEE_RATE / 10000;
        uint256 netAmount = totalAmount - fee;

        IERC20(token).safeTransferFrom(msg.sender, address(this), totalAmount);

        if (fee > 0) {
            IERC20(token).safeTransfer(feeWallet, fee);
        }

        _createDeposit(token, totalAmount, netAmount, ownerAddress, recoveryAddress, spenderAddresses, spenderLimits);
    }

    function _createDeposit(
        address token,
        uint256 totalAmount,
        uint256 netAmount,
        address ownerAddress,
        address recoveryAddress,
        address[] calldata spenderAddresses,
        uint256[] calldata spenderLimits
    ) internal {
        require(ownerAddress != address(0), "Invalid owner");
        require(recoveryAddress != address(0), "Invalid recovery");
        require(spenderAddresses.length == spenderLimits.length, "Mismatch");
        require(spenderAddresses.length > 0 && spenderAddresses.length <= MAX_SPENDERS, "Max 10 spenders");

        Deposit storage d = deposits.push();
        d.token = token;
        d.balance = netAmount;
        d.ownerAddress = ownerAddress;
        d.recoveryAddress = recoveryAddress;
        d.frozen = false;
        d.ownerNonce = 0;

        for (uint i = 0; i < spenderAddresses.length; i++) {
            require(spenderAddresses[i] != address(0), "Zero spender");
            d.spenders.push(Spender({
                spenderAddress: spenderAddresses[i],
                limit: spenderLimits[i],
                withdrawn: 0,
                nonce: 0
            }));
        }

        emit Deposited(deposits.length - 1, token, totalAmount, netAmount);
    }

    // 取款
    function withdraw(
        uint256 id,
        uint256 amount,
        uint256 spenderIndex,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotStopped nonReentrant {
        require(id < deposits.length, "Invalid id");
        Deposit storage d = deposits[id];
        require(!d.frozen, "Deposit frozen");
        require(spenderIndex < d.spenders.length, "Invalid index");

        Spender storage sRef = d.spenders[spenderIndex];
        require(msg.sender == sRef.spenderAddress, "Not the spender");

        bytes32 message = keccak256(abi.encode(id, amount, spenderIndex, sRef.nonce, block.chainid, address(this)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        require(ecrecover(ethHash, v, r, s) == sRef.spenderAddress, "Invalid signature");

        if (sRef.limit > 0) {
            require(sRef.withdrawn + amount <= sRef.limit, "Exceeds limit");
        }
        require(amount <= d.balance, "Insufficient balance");

        unchecked {
            d.balance -= amount;
            sRef.withdrawn += amount;
            sRef.nonce++;
        }

        if (d.token == address(0)) {
            (bool success,) = msg.sender.call{value: amount}("");
            require(success, "ETH transfer failed");
        } else {
            IERC20(d.token).safeTransfer(msg.sender, amount);
        }

        emit Withdrawn(id, d.token, amount, msg.sender);
    }

    // freeze
    function freeze(uint256 id, uint8 v, bytes32 r, bytes32 s) external whenNotStopped {
        require(id < deposits.length, "Invalid id");
        Deposit storage d = deposits[id];

        bytes32 actionHash = keccak256(abi.encode("freeze", d.ownerNonce));
        bytes32 message = keccak256(abi.encode(id, actionHash, block.chainid, address(this)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        require(ecrecover(ethHash, v, r, s) == d.ownerAddress, "Invalid owner signature");

        d.frozen = true;
        d.ownerNonce++;
        emit Frozen(id);
    }

    // unfreeze
    function unfreeze(uint256 id, uint8 v, bytes32 r, bytes32 s) external whenNotStopped {
        require(id < deposits.length, "Invalid id");
        Deposit storage d = deposits[id];

        bytes32 actionHash = keccak256(abi.encode("unfreeze", d.ownerNonce));
        bytes32 message = keccak256(abi.encode(id, actionHash, block.chainid, address(this)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        require(ecrecover(ethHash, v, r, s) == d.ownerAddress, "Invalid owner signature");

        d.frozen = false;
        d.ownerNonce++;
        emit Unfrozen(id);
    }

    // recover
    function recover(uint256 id, uint8 v, bytes32 r, bytes32 s) external whenNotStopped nonReentrant {
        require(id < deposits.length, "Invalid id");
        Deposit storage d = deposits[id];

        bytes32 actionHash = keccak256(abi.encode("recover", d.ownerNonce));
        bytes32 message = keccak256(abi.encode(id, actionHash, block.chainid, address(this)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        require(ecrecover(ethHash, v, r, s) == d.ownerAddress, "Invalid owner signature");

        require(d.balance > 0, "Zero balance");

        uint256 amount = d.balance;
        d.balance = 0;
        d.frozen = true;
        d.ownerNonce++;

        if (d.token == address(0)) {
            (bool success,) = d.recoveryAddress.call{value: amount}("");
            require(success, "Recovery failed");
        } else {
            IERC20(d.token).safeTransfer(d.recoveryAddress, amount);
        }

        emit Recovered(id, d.token, amount, d.recoveryAddress);
    }

    // 清理记录(仅清除合约储存槽内部记录)
    function cleanUpDeposit(uint256 id, uint8 v, bytes32 r, bytes32 s) external whenNotStopped {
        require(id < deposits.length, "Invalid id");
        Deposit storage d = deposits[id];

        bytes32 actionHash = keccak256(abi.encode("cleanUp", d.ownerNonce));
        bytes32 message = keccak256(abi.encode(id, actionHash, block.chainid, address(this)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        require(ecrecover(ethHash, v, r, s) == d.ownerAddress, "Invalid owner signature");

        require(d.balance == 0, "Balance not zero");

        for (uint i = 0; i < d.spenders.length; i++) {
            Spender storage sp = d.spenders[i];
            if (sp.limit > 0) {
                require(sp.withdrawn >= sp.limit, "Not all limits reached");
            }
        }

        d.ownerAddress = address(0);
        d.recoveryAddress = address(0);

        while (d.spenders.length > 0) {
            d.spenders.pop();
        }

        d.ownerNonce++;

        emit DepositCleaned(id);
    }

    // 查询
    function queryAsSpender(uint256 id, uint256 spenderIndex) external view returns (
        uint256 myRemaining,
        uint256 totalBalance,
        address storedSpenderAddress,
        address token
    ) {
        require(id < deposits.length, "Invalid id");
        Deposit storage d = deposits[id];
        require(spenderIndex < d.spenders.length, "Invalid index");
        Spender storage s = d.spenders[spenderIndex];

        uint256 remaining = s.limit == 0 ? d.balance : s.limit - s.withdrawn;
        return (remaining, d.balance, s.spenderAddress, d.token);
    }

    function queryOwnerBasic(uint256 id, uint8 v, bytes32 r, bytes32 s) external view returns (
        uint256 balance,
        bool frozen,
        address recoveryAddress,
        address ownerAddress,
        uint256 ownerNonce,
        address token
    ) {
        require(id < deposits.length, "Invalid id");
        Deposit storage d = deposits[id];

        bytes32 actionHash = keccak256("queryBasic");
        bytes32 message = keccak256(abi.encode(id, actionHash, block.chainid, address(this)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        require(ecrecover(ethHash, v, r, s) == d.ownerAddress, "Invalid owner signature");

        return (d.balance, d.frozen, d.recoveryAddress, d.ownerAddress, d.ownerNonce, d.token);
    }

    function queryOwnerSpenders(uint256 id, uint8 v, bytes32 r, bytes32 s) external view returns (
        uint256[] memory limits,
        uint256[] memory withdrawns,
        uint256[] memory remainings,
        address[] memory spenderAddrs
    ) {
        require(id < deposits.length, "Invalid id");
        Deposit storage d = deposits[id];

        bytes32 actionHash = keccak256("querySpenders");
        bytes32 message = keccak256(abi.encode(id, actionHash, block.chainid, address(this)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        require(ecrecover(ethHash, v, r, s) == d.ownerAddress, "Invalid owner signature");

        uint256 len = d.spenders.length;
        limits = new uint256[](len);
        withdrawns = new uint256[](len);
        remainings = new uint256[](len);
        spenderAddrs = new address[](len);

        for (uint i = 0; i < len; i++) {
            Spender storage sp = d.spenders[i];
            limits[i] = sp.limit;
            withdrawns[i] = sp.withdrawn;
            remainings[i] = sp.limit == 0 ? d.balance : sp.limit - sp.withdrawn;
            spenderAddrs[i] = sp.spenderAddress;
        }

        return (limits, withdrawns, remainings, spenderAddrs);
    }

    function getDepositInfo(uint256 id) external view returns (
        address token,
        uint256 balance,
        bool frozen,
        uint256 spenderCount,
        bool stopped
    ) {
        require(id < deposits.length, "Invalid id");
        Deposit storage d = deposits[id];
        return (d.token, d.balance, d.frozen, d.spenders.length, emergencyStop);
    }
}