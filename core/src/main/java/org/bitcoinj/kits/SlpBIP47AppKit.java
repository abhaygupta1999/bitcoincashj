/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.kits;

import org.bitcoinj.core.*;
import org.bitcoinj.core.bip47.BIP47Account;
import org.bitcoinj.core.slp.*;
import org.bitcoinj.core.slp.nft.NonFungibleSlpToken;
import org.bitcoinj.core.slp.opreturn.SlpOpReturnOutputGenesis;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.net.SlpDbNftDetails;
import org.bitcoinj.net.SlpDbProcessor;
import org.bitcoinj.net.SlpDbTokenDetails;
import org.bitcoinj.net.SlpDbValidTransaction;
import org.bitcoinj.protocols.payments.slp.SlpPaymentSession;
import org.bitcoinj.script.Script;
import org.bitcoinj.store.SPVBlockStore;
import org.bitcoinj.wallet.KeyChainGroupStructure;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.bouncycastle.crypto.params.KeyParameter;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.annotation.Nullable;
import java.io.*;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * <p>Utility class that wraps the boilerplate needed to set up a new SPV bitcoinj app. Instantiate it with a directory
 * and file prefix, optionally configure a few things, then use startAsync and optionally awaitRunning. The object will
 * construct and configure a {@link BlockChain}, {@link SPVBlockStore}, {@link Wallet} and {@link PeerGroup}. Depending
 * on the value of the blockingStartup property, startup will be considered complete once the block chain has fully
 * synchronized, so it can take a while.</p>
 *
 * <p>To add listeners and modify the objects that are constructed, you can either do that by overriding the
 * {@link #onSetupCompleted()} method (which will run on a background thread) and make your changes there,
 * or by waiting for the service to start and then accessing the objects from wherever you want. However, you cannot
 * access the objects this class creates until startup is complete.</p>
 *
 * <p>The asynchronous design of this class may seem puzzling (just use {@link #awaitRunning()} if you don't want that).
 * It is to make it easier to fit bitcoinj into GUI apps, which require a high degree of responsiveness on their main
 * thread which handles all the animation and user interaction. Even when blockingStart is false, initializing bitcoinj
 * means doing potentially blocking file IO, generating keys and other potentially intensive operations. By running it
 * on a background thread, there's no risk of accidentally causing UI lag.</p>
 *
 * <p>Note that {@link #awaitRunning()} can throw an unchecked {@link IllegalStateException}
 * if anything goes wrong during startup - you should probably handle it and use {@link Exception#getCause()} to figure
 * out what went wrong more precisely. Same thing if you just use the {@link #startAsync()} method.</p>
 */
public class SlpBIP47AppKit extends BIP47AppKit {
    private File tokensFile;
    private File nftsFile;
    private long MIN_DUST = 546L;
    private SlpDbProcessor slpDbProcessor;
    private boolean recalculatingTokens = false;
    private boolean recalculatingNfts = false;

    /**
     * Creates a new WalletAppKit, with a newly created {@link Context}. Files will be stored in the given directory.
     */
    public SlpBIP47AppKit(NetworkParameters params, File directory, String filePrefix) {
        this(new Context(params), Script.ScriptType.P2PKH, null, directory, filePrefix);
    }

    /**
     * Creates a new WalletAppKit, with a newly created {@link Context}. Files will be stored in the given directory.
     */
    public SlpBIP47AppKit(NetworkParameters params, Script.ScriptType preferredOutputScriptType,
                          @Nullable KeyChainGroupStructure structure, File directory, String filePrefix) {
        this(new Context(params), preferredOutputScriptType, structure, directory, filePrefix);
    }

    /**
     * Creates a new WalletAppKit, with the given {@link Context}. Files will be stored in the given directory.
     */
    public SlpBIP47AppKit(Context context, Script.ScriptType preferredOutputScriptType,
                          @Nullable KeyChainGroupStructure structure, File directory, String filePrefix) {
        super(context, preferredOutputScriptType, structure, directory, filePrefix);
        this.structure = structure != null ? structure : KeyChainGroupStructure.SLP;
    }

    @Override
    protected void startUp() throws Exception {
        super.startUp();
        File txsDataFile = new File(this.directory(), this.filePrefix + ".txs");
        if (txsDataFile.exists()) {
            this.loadRecordedTxs();
        }
        File tokenDataFile = new File(this.directory(), this.filePrefix + ".tokens");
        this.tokensFile = tokenDataFile;
        if (tokenDataFile.exists()) {
            this.loadTokens();
        }
        File nftDataFile = new File(this.directory(), this.filePrefix + ".nfts");
        this.nftsFile = nftDataFile;
        if (nftDataFile.exists()) {
            this.loadNfts();
        }

        this.slpDbProcessor = new SlpDbProcessor();
    }

    /**
     * <p>Create the account M/47'/0'/0' from the seed as a Bip47Account.</p>
     *
     * <p>After deriving, this wallet's payment code is available in @{link Bip47Wallet.getPaymentCode()}</p>
     */
    @Override
    public void setAccount() {
        byte[] hd_seed = this.restoreFromSeed != null ?
                this.restoreFromSeed.getSeedBytes() :
                this.vWallet.getKeyChainSeed().getSeedBytes();


        DeterministicKey mKey = HDKeyDerivation.createMasterPrivateKey(hd_seed);
        DeterministicKey purposeKey = HDKeyDerivation.deriveChildKey(mKey, 47 | ChildNumber.HARDENED_BIT);
        DeterministicKey coinKey = HDKeyDerivation.deriveChildKey(purposeKey, 245 | ChildNumber.HARDENED_BIT);

        BIP47Account account = new BIP47Account(params, coinKey, 0);

        mAccounts.clear();
        mAccounts.add(account);
    }

    private void saveTokens(ArrayList<SlpToken> slpTokens) {
        try (Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File(this.directory(), tokensFile.getName())), StandardCharsets.UTF_8))) {
            JSONArray json = new JSONArray();
            for (SlpToken slpToken : slpTokens) {
                JSONObject tokenObj = new JSONObject();
                tokenObj.put("tokenId", slpToken.getTokenId());
                tokenObj.put("ticker", slpToken.getTicker());
                tokenObj.put("decimals", slpToken.getDecimals());
                json.put(tokenObj);
            }
            writer.write(json.toString());
            writer.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void saveNfts(ArrayList<NonFungibleSlpToken> nfts) {
        try (Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File(this.directory(), nftsFile.getName())), StandardCharsets.UTF_8))) {
            JSONArray json = new JSONArray();
            for (NonFungibleSlpToken nft : nfts) {
                JSONObject tokenObj = new JSONObject();
                tokenObj.put("tokenId", nft.getTokenId());
                tokenObj.put("nftParentId", nft.getNftParentId());
                tokenObj.put("ticker", nft.getTicker());
                tokenObj.put("decimals", nft.getDecimals());
                json.put(tokenObj);
            }
            writer.write(json.toString());
            writer.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void loadTokens() {
        BufferedReader br = null;
        try {
            FileInputStream is = new FileInputStream(new File(this.directory(), this.tokensFile.getName()));
            br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
            String jsonString = sb.toString();

            try {
                JSONArray tokensJson = new JSONArray(jsonString);
                for (int x = 0; x < tokensJson.length(); x++) {
                    JSONObject tokenObj = tokensJson.getJSONObject(x);
                    String tokenId = tokenObj.getString("tokenId");
                    String ticker = tokenObj.getString("ticker");
                    int decimals = tokenObj.getInt("decimals");
                    SlpToken slpToken = new SlpToken(tokenId, ticker, decimals);
                    if (!this.tokenIsMapped(tokenId)) {
                        this.slpTokens.add(slpToken);
                    }
                }
            } catch (Exception e) {
                this.slpTokens = new ArrayList<>();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                assert br != null;
                br.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void loadNfts() {
        BufferedReader br = null;
        try {
            FileInputStream is = new FileInputStream(new File(this.directory(), this.nftsFile.getName()));
            br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
            String jsonString = sb.toString();

            try {
                JSONArray tokensJson = new JSONArray(jsonString);
                for (int x = 0; x < tokensJson.length(); x++) {
                    JSONObject tokenObj = tokensJson.getJSONObject(x);
                    String tokenId = tokenObj.getString("tokenId");
                    String nftParentId = tokenObj.getString("nftParentId");
                    String ticker = tokenObj.getString("ticker");
                    String name = tokenObj.getString("name");
                    int decimals = tokenObj.getInt("decimals");
                    NonFungibleSlpToken nft = new NonFungibleSlpToken(tokenId, nftParentId, name, ticker, decimals);
                    if (!this.nftIsMapped(tokenId)) {
                        this.nfts.add(nft);
                    }
                }
            } catch (Exception e) {
                this.nfts = new ArrayList<>();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                assert br != null;
                br.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void saveVerifiedTxs(ArrayList<String> recordedSlpTxs) {
        try (Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File(this.directory(), this.filePrefix + ".txs")), StandardCharsets.UTF_8))) {
            StringBuilder text = new StringBuilder();
            for (String txHash : recordedSlpTxs) {
                text.append(txHash).append("\n");
            }
            writer.write(text.toString());
            writer.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void loadRecordedTxs() {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(new File(this.directory(), this.filePrefix + ".txs")));
            String line = br.readLine();
            while (line != null) {
                String txHash = line;
                this.verifiedSlpTxs.add(txHash);
                line = br.readLine();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                assert br != null;
                br.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void recalculateSlpUtxos() {
        if (!recalculatingTokens) {
            recalculatingTokens = true;
            this.slpUtxos.clear();
            this.slpBalances.clear();
            this.nftParentUtxos.clear();
            this.nftParentBalances.clear();
            List<TransactionOutput> utxos = this.wallet().getAllDustUtxos(false, false);
            ArrayList<SlpUTXO> slpUtxosToAdd = new ArrayList<>();
            ArrayList<SlpUTXO> nftParentUtxosToAdd = new ArrayList<>();

            for (TransactionOutput utxo : utxos) {
                Transaction tx = utxo.getParentTransaction();
                if (tx != null) {
                    if (SlpOpReturn.isSlpTx(tx)) {
                        SlpOpReturn slpOpReturn = new SlpOpReturn(tx);
                        String tokenId = slpOpReturn.getTokenId();

                        if(slpOpReturn.getSlpTxType() == SlpOpReturn.SlpTxType.SEND || slpOpReturn.getSlpTxType() == SlpOpReturn.SlpTxType.GENESIS || slpOpReturn.getSlpTxType() == SlpOpReturn.SlpTxType.MINT) {
                            if (!hasTransactionBeenRecorded(tx.getTxId().toString())) {
                                SlpDbValidTransaction validTxQuery = new SlpDbValidTransaction(tx.getTxId().toString());
                                boolean valid = this.slpDbProcessor.isValidSlpTx(validTxQuery.getEncoded());
                                if (valid) {
                                    SlpUTXO slpUTXO = processSlpUtxo(slpOpReturn, utxo);
                                    slpUtxosToAdd.add(slpUTXO);
                                    if (!this.tokenIsMapped(tokenId)) {
                                        this.tryCacheToken(tokenId);
                                    } else {
                                        SlpToken slpToken = this.getSlpToken(tokenId);
                                        this.calculateSlpBalance(slpUTXO, slpToken);
                                    }
                                    this.verifiedSlpTxs.add(tx.getTxId().toString());
                                }
                            } else {
                                SlpUTXO slpUTXO = processSlpUtxo(slpOpReturn, utxo);
                                slpUtxosToAdd.add(slpUTXO);
                                if (!this.tokenIsMapped(tokenId)) {
                                    this.tryCacheToken(tokenId);
                                } else {
                                    SlpToken slpToken = this.getSlpToken(tokenId);
                                    this.calculateSlpBalance(slpUTXO, slpToken);
                                }
                            }
                        } else if(slpOpReturn.getSlpTxType() == SlpOpReturn.SlpTxType.NFT_PARENT_SEND || slpOpReturn.getSlpTxType() == SlpOpReturn.SlpTxType.NFT_PARENT_GENESIS || slpOpReturn.getSlpTxType() == SlpOpReturn.SlpTxType.NFT_PARENT_MINT) {
                            if (!hasTransactionBeenRecorded(tx.getTxId().toString())) {
                                SlpDbValidTransaction validTxQuery = new SlpDbValidTransaction(tx.getTxId().toString());
                                boolean valid = this.slpDbProcessor.isValidSlpTx(validTxQuery.getEncoded());
                                if (valid) {
                                    SlpUTXO slpUTXO = processSlpUtxo(slpOpReturn, utxo);
                                    nftParentUtxosToAdd.add(slpUTXO);
                                    if (!this.tokenIsMapped(tokenId)) {
                                        this.tryCacheToken(tokenId);
                                    } else {
                                        SlpToken slpToken = this.getSlpToken(tokenId);
                                        this.calculateNftParentBalance(slpUTXO, slpToken);
                                    }
                                    this.verifiedSlpTxs.add(tx.getTxId().toString());
                                }
                            } else {
                                SlpUTXO slpUTXO = processSlpUtxo(slpOpReturn, utxo);
                                nftParentUtxosToAdd.add(slpUTXO);
                                if (!this.tokenIsMapped(tokenId)) {
                                    this.tryCacheToken(tokenId);
                                } else {
                                    SlpToken slpToken = this.getSlpToken(tokenId);
                                    this.calculateNftParentBalance(slpUTXO, slpToken);
                                }
                            }
                        }
                    }
                }
            }

            this.slpUtxos.addAll(slpUtxosToAdd);
            this.nftParentUtxos.addAll(nftParentUtxosToAdd);
            this.saveVerifiedTxs(this.verifiedSlpTxs);
            recalculatingTokens = false;
        }
    }

    public void recalculateNftUtxos() {
        if (!recalculatingNfts) {
            recalculatingNfts = true;
            this.nftUtxos.clear();
            this.nftBalances.clear();
            List<TransactionOutput> utxos = this.wallet().getAllDustUtxos(false, false);
            ArrayList<SlpUTXO> slpUtxosToAdd = new ArrayList<>();

            for (TransactionOutput utxo : utxos) {
                Transaction tx = utxo.getParentTransaction();
                if (tx != null) {
                    if (SlpOpReturn.isNftChildTx(tx)) {
                        SlpOpReturn slpOpReturn = new SlpOpReturn(tx);
                        String tokenId = slpOpReturn.getTokenId();

                        if (!hasTransactionBeenRecorded(tx.getTxId().toString())) {
                            SlpDbValidTransaction validTxQuery = new SlpDbValidTransaction(tx.getTxId().toString());
                            boolean valid = this.slpDbProcessor.isValidSlpTx(validTxQuery.getEncoded());
                            if (valid) {
                                SlpUTXO slpUTXO = processSlpUtxo(slpOpReturn, utxo);
                                slpUtxosToAdd.add(slpUTXO);
                                if (!this.nftIsMapped(tokenId)) {
                                    this.tryCacheNft(tokenId);
                                } else {
                                    NonFungibleSlpToken slpToken = this.getNft(tokenId);
                                    this.calculateNftBalance(slpUTXO, slpToken);
                                }
                                this.verifiedSlpTxs.add(tx.getTxId().toString());
                            }
                        } else {
                            SlpUTXO slpUTXO = processSlpUtxo(slpOpReturn, utxo);
                            slpUtxosToAdd.add(slpUTXO);
                            if (!this.nftIsMapped(tokenId)) {
                                this.tryCacheNft(tokenId);
                            } else {
                                NonFungibleSlpToken slpToken = this.getNft(tokenId);
                                this.calculateNftBalance(slpUTXO, slpToken);
                            }
                        }
                    }
                }
            }

            this.nftUtxos.addAll(slpUtxosToAdd);
            this.saveVerifiedTxs(this.verifiedSlpTxs);
            recalculatingNfts = false;
        }
    }

    private SlpUTXO processSlpUtxo(SlpOpReturn slpOpReturn, TransactionOutput utxo) {
        long tokenRawAmount = slpOpReturn.getRawAmountOfUtxo(utxo.getIndex() - 1);
        return new SlpUTXO(slpOpReturn.getTokenId(), tokenRawAmount, utxo, SlpUTXO.SlpUtxoType.NORMAL);
    }

    private void tryCacheToken(String tokenId) {
        if (!this.tokenIsMapped(tokenId)) {
            SlpDbTokenDetails tokenQuery = new SlpDbTokenDetails(tokenId);
            JSONObject tokenData = this.slpDbProcessor.getTokenData(tokenQuery.getEncoded());

            if (tokenData != null) {
                int decimals = tokenData.getInt("decimals");
                String ticker = tokenData.getString("ticker");
                SlpToken slpToken = new SlpToken(tokenId, ticker, decimals);
                this.slpTokens.add(slpToken);
                this.saveTokens(this.slpTokens);
            }
        }
    }

    private void tryCacheNft(String tokenId) {
        if (!this.nftIsMapped(tokenId)) {
            SlpDbNftDetails tokenQuery = new SlpDbNftDetails(tokenId);
            JSONObject tokenData = this.slpDbProcessor.getTokenData(tokenQuery.getEncoded());

            if (tokenData != null) {
                int decimals = tokenData.getInt("decimals");
                String ticker = tokenData.getString("ticker");
                String name = tokenData.getString("name");
                String nftParentId = tokenData.getString("nftParentId");
                NonFungibleSlpToken nft = new NonFungibleSlpToken(tokenId, nftParentId, name, ticker, decimals);
                this.nfts.add(nft);
                this.saveNfts(this.nfts);
            }
        }
    }

    public boolean hasTransactionBeenRecorded(String txid) {
        return this.verifiedSlpTxs.contains(txid);
    }
}
