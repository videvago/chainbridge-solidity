pragma solidity 0.6.4;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";


interface IERC20BurnMint is IERC20 {

    /**
     * @dev Creates `amount` new tokens for `to`.
     *
     * See {IERC20-_mint}.
     *
     * Requirements:
     *
     * - the caller must have the `MINTER_ROLE`.
     */
    function mint(address to, uint256 amount) external;


    /**
     * @dev Destroys `amount` tokens from `account`, deducting from the caller's
     * allowance.
     *
     * See {IERC20-_burn} and {IERC20-allowance}.
     *
     * Requirements:
     *
     * - the caller must have allowance for ``accounts``'s tokens of at least
     * `amount`.
     */
    function burnFrom(address account, uint256 amount) external;
}
