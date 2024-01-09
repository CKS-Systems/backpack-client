import got, { OptionsOfTextResponseBody } from "got";
import crypto from "crypto";
import qs from "qs";

const BACKOFF_EXPONENT = 1.5;
const DEFAULT_TIMEOUT_MS = 5_000;
const BASE_URL = "https://api.backpack.exchange/";

const instructions = {
  public: new Map<string, { url: string; method: string }>([
    ["assets", { url: `${BASE_URL}api/v1/assets`, method: "GET" }],
    ["markets", { url: `${BASE_URL}api/v1/markets`, method: "GET" }],
    ["ticker", { url: `${BASE_URL}api/v1/ticker`, method: "GET" }],
    ["depth", { url: `${BASE_URL}api/v1/depth`, method: "GET" }],
    ["klines", { url: `${BASE_URL}api/v1/klines`, method: "GET" }],
    ["status", { url: `${BASE_URL}api/v1/status`, method: "GET" }],
    ["ping", { url: `${BASE_URL}api/v1/ping`, method: "GET" }],
    ["time", { url: `${BASE_URL}api/v1/time`, method: "GET" }],
    ["trades", { url: `${BASE_URL}api/v1/trades`, method: "GET" }],
    [
      "tradesHistory",
      { url: `${BASE_URL}api/v1/trades/history`, method: "GET" },
    ],
  ]),
  private: new Map<string, { url: string; method: string }>([
    ["balanceQuery", { url: `${BASE_URL}api/v1/capital`, method: "GET" }],
    [
      "depositAddressQuery",
      { url: `${BASE_URL}wapi/v1/capital/deposit/address`, method: "GET" },
    ],
    [
      "depositQueryAll",
      { url: `${BASE_URL}wapi/v1/capital/deposits`, method: "GET" },
    ],
    [
      "fillHistoryQueryAll",
      { url: `${BASE_URL}wapi/v1/history/fills`, method: "GET" },
    ],
    ["orderCancel", { url: `${BASE_URL}api/v1/order`, method: "DELETE" }],
    ["orderCancelAll", { url: `${BASE_URL}api/v1/orders`, method: "DELETE" }],
    ["orderExecute", { url: `${BASE_URL}api/v1/order`, method: "POST" }],
    [
      "orderHistoryQueryAll",
      { url: `${BASE_URL}wapi/v1/history/orders`, method: "GET" },
    ],
    ["orderQuery", { url: `${BASE_URL}api/v1/order`, method: "GET" }],
    ["orderQueryAll", { url: `${BASE_URL}api/v1/orders`, method: "GET" }],
    [
      "withdraw",
      { url: `${BASE_URL}wapi/v1/capital/withdrawals`, method: "POST" },
    ],
    [
      "withdrawalQueryAll",
      { url: `${BASE_URL}wapi/v1/capital/withdrawals`, method: "GET" },
    ],
  ]),
};

// https://stackoverflow.com/questions/71916954/crypto-sign-function-to-sign-a-message-with-given-private-key
const toPkcs8der = (rawB64: string) => {
  var rawPrivate = Buffer.from(rawB64, "base64").subarray(0, 32);
  var prefixPrivateEd25519 = Buffer.from(
    "302e020100300506032b657004220420",
    "hex"
  );
  var der = Buffer.concat([prefixPrivateEd25519, rawPrivate]);
  return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
};
// https://stackoverflow.com/questions/68612396/sign-and-verify-jws-json-web-signature-with-ed25519-keypair
const toSpki = (rawB64: string) => {
  var rawPublic = Buffer.from(rawB64, "base64");
  var prefixPublicEd25519 = Buffer.from("302a300506032b6570032100", "hex");
  var der = Buffer.concat([prefixPublicEd25519, rawPublic]);
  return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
};

/**
 * This method generates a signature for Backpack according to
 * https://docs.backpack.exchange/#section/Authentication/Signing-requests
 * @param  {Object}        request params as an object
 * @param  {UInt8Array}    privateKey
 * @param  {number}        timestamp Unix time in ms that the request was sent
 * @param  {string}        instruction
 * @param  {number}        window Time window in milliseconds that the request is valid for
 * @return {string}        base64 encoded signature to include on request
 */
const getMessageSignature = (
  request: object,
  privateKey: string,
  timestamp: number,
  instruction: string,
  window?: number
): string => {
  function alphabeticalSort(a: string, b: string) {
    return a.localeCompare(b);
  }

  const message = qs.stringify(request, { sort: alphabeticalSort });

  const headerInfo = { timestamp, window: window ?? DEFAULT_TIMEOUT_MS };
  const headerMessage: string = qs.stringify(headerInfo);

  const messageToSign: string =
    "instruction=" +
    instruction +
    "&" +
    (message ? message + "&" : "") +
    headerMessage;
  const signature = crypto.sign(
    null,
    Buffer.from(messageToSign),
    toPkcs8der(privateKey)
  );

  return signature.toString("base64");
};

const rawRequest = async (
  instruction: string,
  headers: object,
  data: object
) => {
  const { url, method } = instructions.private.has(instruction)
    ? instructions.private.get(instruction)!
    : instructions.public.get(instruction)!;
  let fullUrl = url;

  headers["User-Agent"] = "Backpack Typescript API Client";
  headers["Content-Type"] =
    method == "GET"
      ? "application/x-www-form-urlencoded"
      : "application/json; charset=utf-8";

  const options = { headers };

  if (method == "GET") {
    Object.assign(options, { method });
    fullUrl =
      url + (Object.keys(data).length > 0 ? "?" + qs.stringify(data) : "");
  } else if (method == "POST" || method == "DELETE") {
    Object.assign(options, {
      method,
      body: JSON.stringify(data),
    });
  }
  const response = await got(fullUrl, options as OptionsOfTextResponseBody);
  const contentType = response.headers["content-type"];
  if (contentType?.includes("application/json")) {
    const parsed = JSON.parse(response.body, function (_key, value) {
      if (value instanceof Array && value.length == 0) {
        return value;
      }
      if (isNaN(Number(value))) {
        return value;
      }
      return Number(value);
    });

    if (parsed.error && parsed.error.length) {
      const error = parsed.error
        .filter((e: string) => e.startsWith("E"))
        .map((e: string) => e.substr(1));

      if (!error.length) {
        throw new Error("Backpack API returned an unknown error");
      }

      throw new Error(
        `url=${url} body=${options["body"]} err=${error.join(", ")}`
      );
    }
    return parsed;
  } else if (contentType?.includes("text/plain")) {
    return response.body;
  } else {
    return response;
  }
};

/**
 * BackpackClient connects to the Backpack API
 * @param {string}        privateKey base64 encoded
 * @param {string}        publicKey  base64 encoded
 */
export class BackpackClient {
  public config: any;

  constructor(privateKey: string, publicKey: string) {
    this.config = { privateKey, publicKey };

    // Verify that the keys are a correct pair before sending any requests. Ran
    // into errors before with that which were not obvious.
    const pubkeyFromPrivateKey = crypto
      .createPublicKey(toPkcs8der(privateKey))
      .export({ format: "der", type: "spki" })
      .toString("base64");
    const pubkey = toSpki(publicKey)
      .export({ format: "der", type: "spki" })
      .toString("base64");
    if (pubkeyFromPrivateKey != pubkey) {
      throw new Error("Invalid keypair");
    }
  }

  /**
   * This method makes a public or private API request.
   * @param  {String}   method   The API method (public or private)
   * @param  {Object}   params   Arguments to pass to the api call
   * @param  {Number}   retrysLeft
   * @return {Object}   The response object
   */
  private async api(
    method: string,
    params?: object,
    retrysLeft: number = 10
  ): Promise<object> {
    try {
      if (instructions.public.has(method)) {
        return await this.publicMethod(method, params);
      } else if (instructions.private.has(method)) {
        return await this.privateMethod(method, params);
      }
    } catch (e: any) {
      if (retrysLeft > 0) {
        const numTry = 11 - retrysLeft;
        const backOff = Math.pow(numTry, BACKOFF_EXPONENT);
        console.warn(
          "BPX api error",
          {
            method,
            numTry,
            backOff,
          },
          e.toString(),
          e.response && e.response.body ? e.response.body : ''
        );
        await new Promise((resolve) => setTimeout(resolve, backOff * 1_000));
        return await this.api(method, params, retrysLeft - 1);
      } else {
        throw e;
      }
    }
    throw new Error(method + " is not a valid API method.");
  }

  /**
   * This method makes a public API request.
   * @param  {String}   instruction   The API method (public or private)
   * @param  {Object}   params        Arguments to pass to the api call
   * @return {Object}                 The response object
   */
  private async publicMethod(
    instruction: string,
    params: object = {}
  ): Promise<object> {
    const response = await rawRequest(instruction, {}, params);
    return response;
  }

  /**
   * This method makes a private API request.
   * @param  {String}   instruction The API method (public or private)
   * @param  {Object}   params      Arguments to pass to the api call
   * @return {Object}               The response object
   */
  private async privateMethod(
    instruction: string,
    params: any = {}
  ): Promise<object> {
    const timestamp = Date.now();
    const signature = getMessageSignature(
      params,
      this.config.privateKey,
      timestamp,
      instruction
    );
    const headers = {
      "X-Timestamp": timestamp,
      "X-Window": this.config.timeout ?? DEFAULT_TIMEOUT_MS,
      "X-API-Key": this.config.publicKey,
      "X-Signature": signature,
    };

    const response = await rawRequest(instruction, headers, params);
    return response;
  }

  /**
   * https://docs.backpack.exchange/#tag/Capital/operation/get_balances
   */
  async Balance(): Promise<BalanceResponse> {
    return this.api("balanceQuery") as unknown as BalanceResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/Capital/operation/get_deposits
   */
  async Deposits(params?: DepositsRequest): Promise<DepositsResponse> {
    return this.api("depositQueryAll", params) as unknown as DepositsResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/Capital/operation/get_deposit_address
   */
  async DepositAddress(
    params: DepositAddressRequest
  ): Promise<DepositAddressResponse> {
    return this.api(
      "depositAddressQuery",
      params
    ) as unknown as DepositAddressResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/Capital/operation/get_withdrawals
   */
  async Withdrawals(params?: WithdrawalsRequest): Promise<WithdrawalsResponse> {
    return this.api(
      "withdrawalQueryAll",
      params
    ) as unknown as WithdrawalsResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/Capital/operation/request_withdrawal
   */
  async Withdraw(params: WithdrawRequest): Promise<void> {
    this.api("withdraw", params);
  }
  /**
   * https://docs.backpack.exchange/#tag/History/operation/get_order_history
   */
  async OrderHistory(
    params?: OrderHistoryRequest
  ): Promise<OrderHistoryResponse> {
    return this.api(
      "orderHistoryQueryAll",
      params
    ) as unknown as OrderHistoryResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/History/operation/get_fills
   */
  async FillHistory(params?: FillHistoryRequest): Promise<FillHistoryResponse> {
    return this.api(
      "fillHistoryQueryAll",
      params
    ) as unknown as FillHistoryResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/Markets/operation/get_assets
   */
  async Assets(): Promise<AssetsResponse> {
    return this.api("assets") as unknown as AssetsResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/Markets/operation/get_markets
   */
  async Markets(): Promise<MarketsResponse> {
    return this.api("markets") as unknown as MarketsResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/Markets/operation/get_ticker
   */
  async Ticker(params: TickerRequest): Promise<TickerResponse> {
    return this.api("ticker", params) as unknown as TickerResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/Markets/operation/get_depth
   */
  async Depth(params: DepthRequest): Promise<DepthResponse> {
    return this.api("depth", params) as unknown as DepthResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/Markets/operation/get_klines
   */
  async KLines(params: KLinesRequest): Promise<KLinesResponse> {
    return this.api("klines", params) as unknown as KLinesResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/Order/operation/get_order
   */
  async GetOrder(params: GetOrderRequest): Promise<GetOrderResponse> {
    return this.api("orderQuery", params) as unknown as GetOrderResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/Order/operation/execute_order
   */
  async ExecuteOrder(
    params: ExecuteOrderRequest
  ): Promise<ExecuteOrderResponse> {
    return this.api("orderExecute", params) as unknown as ExecuteOrderResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/Order/operation/cancel_order
   */
  async CancelOrder(params: CancelOrderRequest): Promise<CancelOrderResponse> {
    return this.api("orderCancel", params) as unknown as CancelOrderResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/Order/operation/get_open_orders
   */
  async GetOpenOrders(
    params?: GetOpenOrdersRequest
  ): Promise<GetOpenOrdersResponse> {
    return this.api(
      "orderQueryAll",
      params
    ) as unknown as GetOpenOrdersResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/Order/operation/cancel_open_orders
   */
  async CancelOpenOrders(
    params: CancelOpenOrdersRequest
  ): Promise<CancelOpenOrdersResponse> {
    return this.api(
      "orderCancelAll",
      params
    ) as unknown as CancelOpenOrdersResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/System/operation/get_status
   */
  async Status(): Promise<StatusResponse> {
    return this.api("status") as unknown as StatusResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/System/operation/ping
   */
  async Ping(): Promise<PingResponse> {
    return this.api("ping") as unknown as PingResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/System/operation/get_time
   */
  async Time(): Promise<TimeResponse> {
    return this.api("time") as unknown as TimeResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/Trades/operation/get_recent_trades
   */
  async RecentTrades(
    params: RecentTradesRequest
  ): Promise<RecentTradesResponse> {
    return this.api("trades", params) as unknown as RecentTradesResponse;
  }
  /**
   * https://docs.backpack.exchange/#tag/Trades/operation/get_historical_trades
   */
  async HistoricalTrades(
    params: HistoricalTradesRequest
  ): Promise<HistoricalTradesResponse> {
    return this.api(
      "tradesHistory",
      params
    ) as unknown as HistoricalTradesResponse;
  }
}

export type Blockchain = "Solana" | "Ethereum" | "Polygon" | "Bitcoin";
export type SelfTradePrevention =
  | "RejectTaker"
  | "RejectMaker"
  | "RejectBoth"
  | "Allow";
export type TimeInForce = "GTC" | "IOC" | "FOK";
export type OrderStatus =
  | "Cancelled"
  | "Expired"
  | "Filled"
  | "New"
  | "PartiallyFilled"
  | "Triggered";
export type LimitOrder = {
  orderType: "limit";
  id: string;
  clientId?: number;
  symbol: string;
  side: "Bid" | "Ask";
  quantity: number;
  executedQuantity: number;
  quoteQuantity: number;
  executedQuoteQuantity: number;
  triggerPrice?: number;
  timeInForce: TimeInForce;
  selfTradePrevention: SelfTradePrevention;
  status: OrderStatus;
  createdAt: number;
};
export type MarketOrder = {
  orderType: "market";
  id: string;
  clientId?: number;
  symbol: string;
  side: "Bid" | "Ask";
  quantity?: number;
  executedQuantity: number;
  quoteQuantity?: number;
  executedQuoteQuantity: number;
  triggerPrice?: number;
  timeInForce: TimeInForce;
  selfTradePrevention: SelfTradePrevention;
  status: OrderStatus;
  createdAt: number;
};

export type BalanceResponse = {
  [property: string]: {
    available: number;
    locked: number;
    staked: number;
  };
};

export type DepositsRequest = {
  limit?: number;
  offset?: number;
};
export type DepositsResponse = {
  id: number;
  toAddress?: string;
  fromAddress?: string;
  confirmationBlockNumber?: number;
  identifier: string;
  source:
    | "administrator"
    | "solana"
    | "ethereum"
    | "bitcoin"
    | "nuvei"
    | "banxa"
    | "ioFinnet";
  status:
    | "pending"
    | "cancelled"
    | "confirmed"
    | "expired"
    | "initiated"
    | "received"
    | "refunded";
  symbol: string;
  quantity: number;
  createdAt: string;
}[];

export type DepositAddressRequest = {
  blockchain: Blockchain;
};
export type DepositAddressResponse = {
  address: string;
};

export type WithdrawRequest = {
  address: string;
  blockchain: Blockchain;
  clientId?: string;
  quantity: number;
  symbol: string;
  twoFactorToken: string;
};

export type OrderHistoryRequest = {
  limit?: number;
  offset?: number;
};
// Not that this is different from other order endpoints because it is missing
// some fields like createdAt
export type OrderHistoryResponse = {
  id: number;
  orderType: "Market" | "Limit";
  symbol: string;
  side: "Bid" | "Ask";
  price: number;
  triggerPrice: number;
  quantity: number;
  quoteQuantity: number;
  timeInForce: TimeInForce;
  selfTradePrevention: SelfTradePrevention;
  postOnly: boolean;
  status: OrderStatus;
}[];

export type FillHistoryRequest = {
  orderId?: string;
  symbol?: string;
  limit?: number;
  offset?: number;
};
export type FillHistoryResponse = {
  id: number;
  tradeId: number;
  orderId: number;
  symbol: string;
  side: "Bid" | "Ask";
  price: number;
  quantity: number;
  fee: number;
  feeSymbol: string;
  isMaker: boolean;
  timestamp: string;
}[];

export type WithdrawalsRequest = {
  limit?: number;
  offset?: number;
};
export type WithdrawalsResponse = {
  id: number;
  blockchain: Blockchain;
  clientId?: string;
  identifier?: string;
  quantity: number;
  fee: number;
  symbol: string;
  status: "pending" | "confirmed" | "verifying" | "void";
  toAddress: string;
  transactionHash?: string;
  createdAt: string;
}[];

export type AssetsResponse = {
  symbol: string;
  tokens: {
    blockchain: Blockchain;
    depositEnabled: boolean;
    minimumDeposit: number;
    withdrawEnabled: boolean;
    minimumWithdrawal: number;
    maximumWithdrawal: number;
    withdrawalFee: number;
  }[];
}[];

export type MarketsResponse = {
  symbol: string;
  baseSymbol: string;
  quoteSymbol: string;
  filters: {
    price: {
      minPrice: number;
      maxPrice?: number;
      tickSize: number;
    };
    quantity: {
      minQuantity: number;
      maxQuantity?: number;
      stepSize: number;
    };
    leverage?: {
      minLeverage: number;
      maxLeverage: number;
      stepSize: number;
    };
  };
}[];

export type TickerRequest = {
  symbol: string;
};
export type TickerResponse = {
  symbol: string;
  firstPrice: number;
  lastPrice: number;
  priceChange: number;
  priceChangePercent: number;
  high: number;
  low: number;
  volume: number;
  trades: number;
};

export type DepthRequest = {
  symbol: string;
};
export type DepthResponse = {
  asks: [number, number][];
  bids: [number, number][];
  lastUpdated: number;
};

export type KLinesRequest = {
  symbol: string;
  interval:
    | "1m"
    | "3m"
    | "5m"
    | "15m"
    | "30m"
    | "1h"
    | "2h"
    | "4h"
    | "6h"
    | "8h"
    | "12h"
    | "1d"
    | "3d"
    | "1month";
  startTime?: number;
  endTime?: number;
};
export type KLinesResponse = {
  start: string;
  open?: string;
  high?: string;
  low?: string;
  close?: string;
  end?: string;
  volume?: string;
  trades?: string;
};

export type GetOrderRequest = {
  clientId?: number;
  orderId?: string;
  symbol: string;
};
export type GetOrderResponse = LimitOrder | MarketOrder;

export type ExecuteOrderRequest = {
  clientId?: number;
  orderType: "Limit" | "Market";
  postOnly?: boolean;
  price?: number;
  quantity?: number;
  quoteQuantity?: number;
  selfTradePrevention?: SelfTradePrevention;
  side: "Bid" | "Ask";
  symbol: string;
  timeInForce?: TimeInForce;
  triggerPrice?: number;
};
export type ExecuteOrderResponse =
  | LimitOrder
  | MarketOrder
  | {
      id: string;
    };

export type CancelOrderRequest = {
  clientId?: number;
  orderId?: string;
  symbol: string;
};
export type CancelOrderResponse =
  | LimitOrder
  | MarketOrder
  | {
      id: string;
    };

export type GetOpenOrdersRequest = {
  symbol?: string;
};
export type GetOpenOrdersResponse = (LimitOrder | MarketOrder)[];

export type CancelOpenOrdersRequest = {
  symbol: string;
};
export type CancelOpenOrdersResponse = (LimitOrder | MarketOrder)[];

export type StatusResponse = {
  status: "Ok" | "Maintenance";
  message?: string;
};

export type PingResponse = "pong";
export type TimeResponse = number;

export type RecentTradesRequest = {
  symbol: string;
  limit?: number;
};
export type RecentTradesResponse = {
  id: number;
  price: number;
  quantity: number;
  quoteQuantity: number;
  timestamp: number;
  isBuyerMaker: boolean;
}[];

export type HistoricalTradesRequest = {
  symbol: string;
  limit?: number;
  offset?: number;
};
export type HistoricalTradesResponse = {
  id: number;
  price: number;
  quantity: number;
  quoteQuantity: number;
  timestamp: number;
  isBuyerMaker: boolean;
}[];
