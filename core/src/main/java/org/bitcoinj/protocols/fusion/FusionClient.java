package org.bitcoinj.protocols.fusion;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import fusion.Fusion;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.Pedersen;
import org.bitcoinj.crypto.SchnorrBlindSignatureRequest;
import org.bitcoinj.crypto.SchnorrSignature;
import org.bitcoinj.protocols.fusion.models.*;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptOpCodes;
import org.bitcoinj.wallet.Wallet;
import org.bouncycastle.util.encoders.Hex;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

public class FusionClient {
    private final int STANDARD_TIMEOUT = 3;
    private final int WARMUP_TIME = 30;
    private final int WARMUP_SLOP = 3;
    private final long MIN_OUTPUT = 10000;
    private final long MAX_CLOCK_DISCREPANCY = 5;
    private final long MAX_EXCESS_FEE = 10000;
    private final long MAX_COMPONENTS = 40;
    private final long MIN_TX_COMPONENTS = 11;
    private final long MAX_COMPONENT_FEERATE = 5000;
    private final long MAX_FEE = MAX_COMPONENT_FEERATE * 7 + MAX_EXCESS_FEE;
    private SSLSocket socket;
    private String host;
    private int port;
    private BufferedOutputStream out;
    private BufferedInputStream in;
    private byte[] magicBytes;
    private Wallet wallet;
    private Pedersen pedersen;

    private ArrayList<Pair<TransactionOutput, ECKey>> inputs = new ArrayList<>();
    private HashMap<Long, ArrayList<Long>> tierOutputs = new HashMap<>();
    private ArrayList<Pair<Script, Long>> outputs = new ArrayList<>();
    private HashMap<Long, Long> safetyExcessFees = new HashMap<>();
    private long numComponents;
    private long componentFeeRate;
    private long minExcessFee;
    private long maxExcessFee;
    private ArrayList<Tier> availableTiers;
    private long tier;
    private long safetyExcessFee;
    private long safetySumIn;

    private byte[] lastHash;
    private byte[] sessionHash;

    //TIME VARIABLES
    private double tFusionBegin = 0;
    private double covertT0 = 0;

    public ArrayList<PoolStatus> poolStatuses = new ArrayList<>();

    private FusionListener listener;

    public FusionClient(String host, int port, ArrayList<TransactionOutput> coins, Wallet wallet, FusionListener listener) throws IOException {
        SSLSocketFactory factory = (SSLSocketFactory)SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket)factory.createSocket(host, port);
        socket.setTcpNoDelay(true);
        socket.setKeepAlive(true);
        socket.setUseClientMode(true);
        socket.startHandshake();
        this.pedersen = new Pedersen(Hex.decode("0243617368467573696f6e2067697665732075732066756e676962696c6974792e"));
        this.socket = socket;
        this.wallet = wallet;
        for(TransactionOutput coin : coins) {
            ECKey key = this.wallet.findKeyFromAddress(coin.getAddressFromP2PKHScript(wallet.getParams()));
            this.inputs.add(Pair.of(coin, key));
        }
        this.availableTiers = new ArrayList<>();
        this.magicBytes = Hex.decode("765be8b4e4396dcf");
        this.host = host;
        this.port = port;
        out = new BufferedOutputStream(socket.getOutputStream());
        in = new BufferedInputStream(socket.getInputStream());
        this.listener = listener;
        greet();
    }

    public FusionClient updateUtxos(ArrayList<TransactionOutput> coins) throws IOException {
        System.out.println("Updating utxos...");
        this.out.close();
        this.in.close();
        this.socket.close();
        this.socket = null;
        this.out = null;
        this.in = null;
        this.lastHash = null;
        this.sessionHash = null;
        this.tFusionBegin = 0;
        this.covertT0 = 0;
        this.tier = 0;
        this.listener.onFusionStatus(FusionStatus.NOT_FUSING);
        this.poolStatuses = new ArrayList<>();
        this.availableTiers = new ArrayList<>();
        this.inputs = new ArrayList<>();
        this.tierOutputs = new HashMap<>();
        this.outputs = new ArrayList<>();
        System.out.println("Updated!");
        return new FusionClient(this.host, this.port, coins, this.wallet, this.listener);
    }

    public void sendMessage(Fusion.ClientMessage clientMessage) throws IOException {
        int size = clientMessage.toByteArray().length;

        UnsafeByteArrayOutputStream bos = new UnsafeByteArrayOutputStream();
        bos.write(magicBytes);

        ByteBuffer sizeBuf = ByteBuffer.allocate(4);
        sizeBuf.putInt(size);
        bos.write(sizeBuf.array());

        bos.write(clientMessage.toByteArray());
        out.write(bos.toByteArray());
        out.flush();

        System.out.println("sent: " + Hex.toHexString(bos.toByteArray()));
    }

    public Fusion.ServerMessage receiveMessage(double timeout) {
        try {
            this.socket.setSoTimeout((int)(timeout*1000D));
            byte[] prefixBytes = readNBytes(in, 12);
            if (prefixBytes.length == 0) return null;
            byte[] sizeBytes = Arrays.copyOfRange(prefixBytes, 8, 12);
            int bufferSize = ByteBuffer.wrap(sizeBytes).getInt();
            return Fusion.ServerMessage.parseFrom(readNBytes(in, bufferSize));
        } catch (IOException e) {
            e.printStackTrace();
            listener.onFusionStatus(FusionStatus.FAILED);
        }

        return null;
    }

    public byte[] readNBytes(BufferedInputStream in, int len) throws IOException {
        if (len < 0) {
            throw new IllegalArgumentException("len < 0");
        } else {
            List<byte[]> bufs = null;
            byte[] result = null;
            int total = 0;
            int remaining = len;

            int n;
            do {
                byte[] buf = new byte[Math.min(remaining, 8192)];

                int nread;
                for(nread = 0; (n = in.read(buf, nread, Math.min(buf.length - nread, remaining))) > 0; remaining -= n) {
                    nread += n;
                }

                if (nread > 0) {
                    if (2147483639 - total < nread) {
                        throw new OutOfMemoryError("Required array size too large");
                    }

                    total += nread;
                    if (result == null) {
                        result = buf;
                    } else {
                        if (bufs == null) {
                            bufs = new ArrayList();
                            bufs.add(result);
                        }

                        bufs.add(buf);
                    }
                }
            } while(n >= 0 && remaining > 0);

            if (bufs == null) {
                if (result == null) {
                    return new byte[0];
                } else {
                    return result.length == total ? result : Arrays.copyOf(result, total);
                }
            } else {
                result = new byte[total];
                int offset = 0;
                remaining = total;

                int count;
                for(Iterator var12 = bufs.iterator(); var12.hasNext(); remaining -= count) {
                    byte[] b = (byte[])var12.next();
                    count = Math.min(b.length, remaining);
                    System.arraycopy(b, 0, result, offset, count);
                    offset += count;
                }

                return result;
            }
        }
    }

    public SSLSocket getSocket() {
        return socket;
    }

    public void stopConnection() throws IOException {
        in.close();
        out.close();
        socket.close();
        in = null;
        out = null;
        socket = null;
    }

    public void greet() throws IOException {
        //construct clientHello message to greet server
        Fusion.ClientHello clientHello = Fusion.ClientHello.newBuilder()
                .setVersion(ByteString.copyFrom("alpha13".getBytes()))
                .setGenesisHash(ByteString.copyFrom(Hex.decode("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")))
                .build();
        Fusion.ClientMessage clientMessage = Fusion.ClientMessage.newBuilder()
                .setClienthello(clientHello)
                .build();
        //send message to server
        this.sendMessage(clientMessage);
        Fusion.ServerMessage serverMessage = this.receiveMessage(5);

        //check if message received is serverhello type
        if(serverMessage.hasServerhello()) {
            Fusion.ServerHello serverHello = serverMessage.getServerhello();
            System.out.println(serverHello);
            this.numComponents = serverHello.getNumComponents();
            this.componentFeeRate = serverHello.getComponentFeerate();
            this.minExcessFee = serverHello.getMinExcessFee();
            this.maxExcessFee = serverHello.getMaxExcessFee();
            for(long tier : serverHello.getTiersList()) {
                //construct tiers list
                availableTiers.add(new Tier(tier));
            }

            if(this.inputs.isEmpty()) {
                System.out.println("Started with no coins");
                return;
            }

            this.allocateOutputs();
        }
    }

    public void allocateOutputs() {
        long numInputs = this.inputs.size();

        long maxComponents = Math.min(numComponents, MAX_COMPONENTS);
        long maxOutputs = maxComponents - numInputs;
        if(maxOutputs < 1) {
            System.out.println("Too many inputs (" + numInputs + " >= " + maxComponents);
            return;
        }

        HashMap<String, ECKey> uniqueKeys = new HashMap<>();
        for(Pair<TransactionOutput, ECKey> pair : this.inputs) {
            String key = pair.getRight().getPublicKeyAsHex();
            if(!uniqueKeys.containsKey(key)) {
                uniqueKeys.put(key, pair.getRight());
            }
        }
        long numDistinct = uniqueKeys.size();
        long minOutputs = Math.max(MIN_TX_COMPONENTS - numDistinct, 1);

        if(maxOutputs < minOutputs) {
            System.out.println("Too few distinct inputs selected (" + numDistinct + "); cannot satisfy output count constraint (>=" + minOutputs + ", <=" + maxOutputs + ")");
            return;
        }

        long sumInputsValue = 0;
        long inputFees = 0;
        for(Pair<TransactionOutput, ECKey> pair : this.inputs) {
            sumInputsValue += pair.getLeft().getValue().value;
            long sizeOfInput = sizeOfInput(pair.getRight().getPubKey());
            long componentFee = componentFee(sizeOfInput, this.componentFeeRate);
            inputFees += componentFee;
        }
        long availableForOutputs = (sumInputsValue - inputFees - this.minExcessFee);
        long feePerOutput = componentFee(34, this.componentFeeRate);
        long offsetPerOutput = MIN_OUTPUT + feePerOutput;

        if(availableForOutputs < offsetPerOutput) {
            System.out.println("Selected inputs had too little value");
            return;
        }

        Random rng = new Random();
        HashMap<Long, ArrayList<Long>> tierOutputs = new HashMap<>();
        HashMap<Long, Long> excessFees = new HashMap<>();
        for(Tier tier : this.availableTiers) {
            long fuzzFeeMax = tier.getTierSize() / 1000000;
            long fuzzFeeMaxReduced = Math.min(Math.min(fuzzFeeMax, MAX_EXCESS_FEE - this.minExcessFee), this.maxExcessFee - this.minExcessFee);
            if(fuzzFeeMaxReduced < 0)
                continue;

            long fuzzFee = rng.nextInt((int) (fuzzFeeMaxReduced + 1));
            long reducedAvailableForOutputs = availableForOutputs - fuzzFee;

            if(fuzzFee > fuzzFeeMaxReduced && fuzzFeeMaxReduced > fuzzFeeMax)
                continue;

            if(reducedAvailableForOutputs < offsetPerOutput)
                continue;

            ArrayList<Long> outputs = randomOutputsForTier(rng, reducedAvailableForOutputs, tier, offsetPerOutput, maxOutputs);
            if(outputs.isEmpty() || outputs.size() < minOutputs)
                continue;

            for(int x = 0; x < outputs.size(); x++) {
                long output = outputs.get(x);
                long adjusted = output - feePerOutput;
                outputs.set(x, adjusted);
            }

            if((this.inputs.size() + outputs.size()) > MAX_COMPONENTS)
                continue;

            long excessFee = (sumInputsValue - inputFees - reducedAvailableForOutputs);
            excessFees.put(tier.getTierSize(), excessFee);
            tierOutputs.put(tier.getTierSize(), outputs);
        }

        this.tierOutputs = tierOutputs;
        this.safetySumIn = sumInputsValue;
        this.safetyExcessFees = excessFees;
        System.out.println("Possible tiers: " + tierOutputs);
        this.registerAndWait();
    }

    public ArrayList<Long> randomOutputsForTier(Random rng, long inputAmount, Tier tier, long offset, long maxCount) {
        if(inputAmount < offset)
            return new ArrayList<>();

        double lambd = 1./tier.getTierSize();
        long remaining = inputAmount;
        ArrayList<Double> values = new ArrayList<>();
        for(int x = 0; x < maxCount+1; x++) {
            double val = expovariate(rng, lambd);
            remaining -= Math.ceil(val) + offset;
            if(remaining < 0)
                break;
            values.add(val);
        }

        if(values.size() > maxCount) return new ArrayList<>();
        if(values.isEmpty()) return new ArrayList<>();

        long desiredRandomSum = inputAmount - values.size() * offset;
        if(desiredRandomSum < 0) {
            return new ArrayList<>();
        }

        ArrayList<Double> cumSum = runningSum(values);
        double sum = cumSum.get(cumSum.size()-1);

        double rescale = desiredRandomSum / sum;
        ArrayList<Long> normedCumSum = new ArrayList<>();
        for(double val : cumSum) {
            normedCumSum.add(Math.round(rescale * val));
        }
        long normedSum = normedCumSum.get(normedCumSum.size()-1);

        if(normedSum != desiredRandomSum) {
            return new ArrayList<>();
        }

        ArrayList<Long> concat = new ArrayList<>();
        concat.add(0L);
        concat.addAll(normedCumSum);
        List<List<Long>> zipped = zip(normedCumSum, concat);

        ArrayList<Long> differences = new ArrayList<>();
        for(List<Long> pair : zipped) {
            if(pair.size() > 1) {
                long a = pair.get(0);
                long b = pair.get(1);
                differences.add(a - b);
            }
        }
        ArrayList<Long> result = new ArrayList<>();
        for(long difference : differences) {
            result.add(offset + difference);
        }

        long resultSum = 0;
        for(long val : result) {
            resultSum += val;
        }

        if(resultSum == inputAmount) {
            return result;
        } else {
            return new ArrayList<>();
        }
    }

    public void registerAndWait() {
        Fusion.JoinPools joinPools = Fusion.JoinPools.newBuilder()
                .addAllTiers(this.tierOutputs.keySet())
                .build();
        Fusion.ClientMessage clientMessage = Fusion.ClientMessage.newBuilder()
                .setJoinpools(joinPools)
                .build();
        try {
            this.sendMessage(clientMessage);
            System.out.println("inputs: " + this.inputs);
            System.out.println("Registered for tiers.");

            Fusion.ServerMessage serverMessage;
            while(true) {
                try {
                    serverMessage = receiveMessage(10);
                    if (serverMessage != null) {
                        if (serverMessage.hasFusionbegin()) {
                            System.out.println("STARTING FUSION!");
                            break;
                        } else if (serverMessage.hasTierstatusupdate()) {
                            Fusion.TierStatusUpdate update = serverMessage.getTierstatusupdate();
                            poolStatuses = new ArrayList<>();
                            for (long tier : tierOutputs.keySet()) {
                                Fusion.TierStatusUpdate.TierStatus status = update.getStatusesOrThrow(tier);
                                PoolStatus poolStatus = new PoolStatus(tier, status.getPlayers(), status.getMinPlayers(), status.getTimeRemaining());
                                poolStatuses.add(poolStatus);
                                this.listener.onPoolStatus(poolStatuses);
                            }
                        }
                    }
                } catch(Exception e) {
                    e.printStackTrace();
                    listener.onFusionStatus(FusionStatus.FAILED);
                }
            }

            if(serverMessage.hasFusionbegin()) {
                Fusion.FusionBegin fusionBegin = serverMessage.getFusionbegin();
                tFusionBegin = System.currentTimeMillis()/1000D;
                double roundTime = fusionBegin.getServerTime();
                double clockMismatch = roundTime - (System.currentTimeMillis()/1000D);
                if (Math.abs(clockMismatch) > MAX_CLOCK_DISCREPANCY) {
                    listener.onFusionStatus(FusionStatus.FAILED);
                    return;
                }
                listener.onFusionStatus(FusionStatus.CREATING_TOR_CONNECTIONS);
                CovertSubmitter covertSubmitter = startCovert(serverMessage);
                this.safetyExcessFee = safetyExcessFees.get(serverMessage.getFusionbegin().getTier());

                while(true) {
                    try {
                        FusionStatus status = runRound(covertSubmitter);
                        this.listener.onFusionStatus(status);
                        if(status == FusionStatus.FUSED || status == FusionStatus.FAILED) {
                            socket.close();
                            covertSubmitter.closeConnections();
                            break;
                        }
                    } catch(Exception e) {
                        e.printStackTrace();
                        socket.close();
                        covertSubmitter.closeConnections();
                        listener.onFusionStatus(FusionStatus.FAILED);
                        break;
                    }
                }

            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private CovertSubmitter startCovert(Fusion.ServerMessage serverMessage) {
        Fusion.FusionBegin fusionBegin = serverMessage.getFusionbegin();
        this.tier = fusionBegin.getTier();
        ArrayList<Long> outputs = tierOutputs.get(this.tier);
        for(long output : outputs) {
            Address address = wallet.freshReceiveAddress();
            Script script = ScriptBuilder.createOutputScript(address);
            this.outputs.add(Pair.of(script, output));
        }

        String covertDomain = fusionBegin.getCovertDomain().toString(StandardCharsets.US_ASCII);
        int covertPort = fusionBegin.getCovertPort();

        try {
            this.lastHash = calcInitialHash(this.tier, fusionBegin.getCovertDomain(), covertPort, fusionBegin.getCovertSsl(), fusionBegin.getServerTime());
        } catch (IOException e) {
            e.printStackTrace();
        }

        CovertSubmitter covertSubmitter = new CovertSubmitter(covertDomain, covertPort, this.numComponents, 6);
        covertSubmitter.scheduleConnections();

        double tend = tFusionBegin + (WARMUP_TIME - WARMUP_SLOP - 1);
        double remTime = tend-(System.currentTimeMillis()/1000D);
        try {
            System.out.println("Sleeping for " + remTime + "s");
            Thread.sleep((int)remTime*1000L);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        return covertSubmitter;
    }

    private FusionStatus runRound(CovertSubmitter covertSubmitter) throws Exception {
        Fusion.ServerMessage serverMessage = receiveMessage((2 * WARMUP_SLOP + STANDARD_TIMEOUT));

        if(serverMessage == null) {
            System.out.println("Could not receive message!");
            return FusionStatus.FAILED;
        }

        if(serverMessage.hasStartround()) {
            Fusion.StartRound startRound = serverMessage.getStartround();
            covertT0 = System.currentTimeMillis()/1000D;
            long roundTime = startRound.getServerTime();

            double clockMismatch = roundTime - (System.currentTimeMillis()/1000D);
            if (Math.abs(clockMismatch) > MAX_CLOCK_DISCREPANCY) {
                return FusionStatus.FAILED;
            }

            if(tFusionBegin != 0) {
                double lag = covertT0 - tFusionBegin - WARMUP_TIME;
                if(Math.abs(lag) > WARMUP_SLOP) {
                    System.out.println("Warmup period too different from expectation");
                    return FusionStatus.FAILED;
                }
                this.tFusionBegin = 0;
            }

            long inputFees = 0;
            for(Pair<TransactionOutput, ECKey> pair : this.inputs) {
                inputFees += componentFee(sizeOfInput(pair.getRight().getPubKey()), this.componentFeeRate);
            }

            long outputFees = this.outputs.size() * componentFee(34, this.componentFeeRate);

            long sumIn = 0;
            for(Pair<TransactionOutput, ECKey> pair : this.inputs) {
                sumIn += pair.getLeft().getValue().value;
            }

            long sumOut = 0;
            for(Pair<Script, Long> output : this.outputs) {
                sumOut += output.getRight();
            }

            long totalFee = sumIn - sumOut;
            long excessFee = totalFee - inputFees - outputFees;
            HashMap<String, Boolean> safetyChecks = new HashMap<>();
            safetyChecks.put("SUMIN==SAFETYSUMIN", sumIn == this.safetySumIn);
            safetyChecks.put("EXCESSFEE==SAFETYEXCESSFEE", excessFee == this.safetyExcessFee);
            safetyChecks.put("EXCESSFEE<=MAXEXCESSFEE", excessFee <= MAX_EXCESS_FEE);
            safetyChecks.put("TOTALFEE<=MAXFEE", totalFee <= MAX_FEE);
            System.out.println("SUMIN==SAFETYSUMIN: " + sumIn + " vs. " + this.safetySumIn);
            System.out.println("EXCESSFEE==SAFETYEXCESSFEE: " + excessFee + " vs. " + this.safetyExcessFee);
            System.out.println("EXCESSFEE<=MAXEXCESSFEE: " + excessFee + " vs. " + MAX_EXCESS_FEE);
            System.out.println("TOTALFEE<=MAXFEE: " + totalFee + " vs. " + MAX_FEE);
            for(String check : safetyChecks.keySet()) {
                boolean value = safetyChecks.get(check);
                if(!value) {
                    System.out.println("SAFETY CHECK FAILED! > " + check);
                    return FusionStatus.FAILED;
                }
            }

            byte[] roundPubKey = startRound.getRoundPubkey().toByteArray();
            List<ByteString> blindNoncePoints = startRound.getBlindNoncePointsList();

            if(blindNoncePoints.size() != this.numComponents) {
                System.out.println("blind nonce miscount");
                return FusionStatus.FAILED;
            }

            long numBlanks = this.numComponents - this.inputs.size() - this.outputs.size();

            this.listener.onFusionStatus(FusionStatus.GENERATING_COMPONENTS);
            GeneratedComponents generatedComponents = genComponents(numBlanks, this.inputs, this.outputs, componentFeeRate);
            if(!BigInteger.valueOf(excessFee).equals(generatedComponents.getSumAmounts())) {
                System.out.println("excess fee does not equal pedersen amount");
                return FusionStatus.FAILED;
            }
            if(blindNoncePoints.size() != generatedComponents.getComponents().size()) {
                System.out.println("Error! Mismatched size! " + blindNoncePoints.size() + " vs. " + generatedComponents.getComponents().size());
                return FusionStatus.FAILED;
            }

            this.listener.onFusionStatus(FusionStatus.MAKING_COMMITMENTS);
            ArrayList<ByteString> myCommitments = new ArrayList<>();
            ArrayList<ByteString> myComponents = new ArrayList<>();
            ArrayList<ByteString> blindSignatureRequestsByteString = new ArrayList<>();
            ArrayList<SchnorrBlindSignatureRequest> blindSignatureRequests = new ArrayList<>();
            for(int x = 0; x < blindNoncePoints.size(); x++) {
                byte[] R = blindNoncePoints.get(x).toByteArray();
                byte[] commitSer = generatedComponents.getComponents().get(x).getCommitSer();
                byte[] compSer = generatedComponents.getComponents().get(x).getCompSer();
                SchnorrBlindSignatureRequest schnorrBlindSignatureRequest = new SchnorrBlindSignatureRequest(roundPubKey, R, Sha256Hash.hash(compSer));
                blindSignatureRequestsByteString.add(ByteString.copyFrom(schnorrBlindSignatureRequest.getRequest()));
                blindSignatureRequests.add(schnorrBlindSignatureRequest);

                //commitments
                ByteString commitmentByteString = ByteString.copyFrom(commitSer);
                myCommitments.add(commitmentByteString);

                //components
                ByteString componentByteString = ByteString.copyFrom(compSer);
                myComponents.add(componentByteString);
            }

            byte[] randomNumber = new SecureRandom().generateSeed(32);

            Fusion.PlayerCommit playerCommit = Fusion.PlayerCommit.newBuilder()
                    .setRandomNumberCommitment(ByteString.copyFrom(Sha256Hash.hash(randomNumber)))
                    .setPedersenTotalNonce(ByteString.copyFrom(generatedComponents.getPedersenTotalNonce()))
                    .setExcessFee(excessFee)
                    .addAllInitialCommitments(myCommitments)
                    .addAllBlindSigRequests(blindSignatureRequestsByteString)
                    .build();
            Fusion.ClientMessage clientMessage = Fusion.ClientMessage.newBuilder()
                    .setPlayercommit(playerCommit)
                    .build();

            if(socket.isClosed() || !socket.isConnected()) {
                covertSubmitter.closeConnections();
                System.out.println("To be respectful to the Fusion server, if we have any sort of connection issue we should disconnect before making a commitment.");
                return FusionStatus.FAILED;
            }

            this.listener.onFusionStatus(FusionStatus.SUBMITTING_COMMITMENTS);
            this.sendMessage(clientMessage);

            Fusion.ServerMessage blindSigServerMessage = this.receiveMessage(covertT0 + 5);
            if(blindSigServerMessage == null) {
                System.out.println("blindSigServerMessage1 is null");
                return FusionStatus.FAILED;
            }

            if(blindSigServerMessage.hasBlindsigresponses()) {
                System.out.println("Has blindsigresponse msg");
                Fusion.BlindSigResponses blindSigResponses = blindSigServerMessage.getBlindsigresponses();
                ArrayList<byte[]> scalars = new ArrayList<>();
                for(ByteString sByteString : blindSigResponses.getScalarsList()) {
                    scalars.add(sByteString.toByteArray());
                }

                if(scalars.size() != blindSignatureRequests.size()) {
                    System.out.println("scalars != blindSigRequests: " + scalars.size() + " vs. " + blindSignatureRequests.size());
                    return FusionStatus.FAILED;
                }

                this.listener.onFusionStatus(FusionStatus.PRODUCING_BLIND_SIGNATURES);
                ArrayList<byte[]> blindSigs = new ArrayList<>();
                for(int x = 0; x < scalars.size(); x++) {
                    SchnorrBlindSignatureRequest r = blindSignatureRequests.get(x);
                    byte[] sig = r.blindFinalize(scalars.get(x));
                    if(sig != null) {
                        blindSigs.add(sig);
                    }
                }

                double remTime = 5d - covertClock();
                if(remTime < 0) {
                    System.out.println("Arrived at covert-component phase too slowly.");
                }
                System.out.println("Remtime: " + remTime);
                Thread.sleep((int)(remTime*1000D));

                if(myComponents.size() != blindSigs.size()) {
                    System.out.println("My components size != blind Sigs size!");
                    return FusionStatus.FAILED;
                }

                ArrayList<Fusion.CovertMessage> covertMessages = new ArrayList<>();
                for(int x = 0; x < myComponents.size(); x++) {
                    ByteString component = myComponents.get(x);
                    byte[] sig = blindSigs.get(x);
                    Fusion.CovertComponent covertComponent = Fusion.CovertComponent.newBuilder()
                            .setRoundPubkey(ByteString.copyFrom(roundPubKey))
                            .setComponent(component)
                            .setSignature(ByteString.copyFrom(sig))
                            .build();
                    Fusion.CovertMessage covertMessage = Fusion.CovertMessage.newBuilder()
                            .setComponent(covertComponent)
                            .build();
                    covertMessages.add(covertMessage);
                }

                listener.onFusionStatus(FusionStatus.COVERTLY_SENDING_COMPONENTS);
                covertSubmitter.scheduleSubmissions(covertMessages, covertT0 + 5, covertT0 + 15);

                listener.onFusionStatus(FusionStatus.RECEIVING_ALL_COMMITMENTS);
                Fusion.ServerMessage allCommitmentsServerMsg = this.receiveMessage(+20);
                if(allCommitmentsServerMsg.hasAllcommitments()) {
                    System.out.println("Has all commitments msg");
                    Fusion.AllCommitments allCommitmentsMsg = allCommitmentsServerMsg.getAllcommitments();
                    List<ByteString> allCommitments = allCommitmentsMsg.getInitialCommitmentsList();

                    for(ByteString commitment : myCommitments) {
                        try {
                            int index = allCommitments.indexOf(commitment);
                            if(index == -1) {
                                System.out.println("missing commitment");
                                return FusionStatus.FAILED;
                            }
                        } catch(Exception e) {
                            System.out.println("missing commitment");
                            return FusionStatus.FAILED;
                        }
                    }

                    listener.onFusionStatus(FusionStatus.RECEIVING_ALL_COMPONENTS);
                    Fusion.ServerMessage shareCovertComponentsServerMsg = this.receiveMessage(+20);
                    if(shareCovertComponentsServerMsg.hasSharecovertcomponents()) {
                        Fusion.ShareCovertComponents shareCovertComponentsMsg = shareCovertComponentsServerMsg.getSharecovertcomponents();
                        String msgSessionHash = Hex.toHexString(shareCovertComponentsMsg.getSessionHash().toByteArray());
                        List<ByteString> allComponents = shareCovertComponentsMsg.getComponentsList();
                        boolean skipSignatures = shareCovertComponentsMsg.getSkipSignatures();

                        if(covertClock() > 20) {
                            System.out.println("Shared components message arrived too slowly.");
                            return FusionStatus.FAILED;
                        }

                        ArrayList<Integer> componentIdxes = new ArrayList<>();
                        for(ByteString component : myComponents) {
                            try {
                                int index = allComponents.indexOf(component);
                                if(index == -1) {
                                    System.out.println("missing component");
                                    return FusionStatus.FAILED;
                                } else {
                                    System.out.println("has component!");
                                    componentIdxes.add(index);
                                }
                            } catch(Exception e) {
                                System.out.println("missing component");
                                return FusionStatus.FAILED;
                            }
                        }

                        System.out.println("Previous hash: " + Hex.toHexString(lastHash));
                        this.lastHash = this.sessionHash = calcRoundHash(lastHash, roundPubKey, roundTime, allCommitments, allComponents);
                        String sessionHashBs = Hex.toHexString(this.sessionHash);
                        System.out.println("Our session hash: " + sessionHashBs);
                        if(shareCovertComponentsMsg.hasSessionHash() && !msgSessionHash.equals(sessionHashBs)) {
                            System.out.println("Session hashes do not match!");
                            return FusionStatus.FAILED;
                        }

                        if(!skipSignatures) {
                            System.out.println("Submitting signatures...");
                            Transaction tx = constructTransaction(allComponents, sessionHash);
                            ArrayList<Fusion.CovertMessage> covertSignatureMessages = new ArrayList<>();
                            listener.onFusionStatus(FusionStatus.SIGNING);
                            for(TransactionInput input : tx.getInputs()) {
                                TransactionOutput output = input.findConnectedOutput(wallet);
                                if(output == null) {
                                    System.out.println("OUTPUT IS NULL!");
                                    continue;
                                }

                                Address address = output.getAddressFromP2PKHScript(wallet.getParams());
                                if(address == null) {
                                    System.out.println("ADDRESS IS NULL!");
                                    continue;
                                }

                                ECKey key = wallet.findKeyFromAddress(address);
                                if(output.isMine(wallet)) {
                                    System.out.println("Calculating signature...");
                                    SchnorrSignature schnorrSignature = tx.calculateSchnorrSignature(
                                            input.getIndex(),
                                            key,
                                            output.getScriptPubKey().getProgram(),
                                            output.getValue(),
                                            Transaction.SigHash.ALL,
                                            false
                                    );

                                    Fusion.CovertTransactionSignature covertTransactionSignature = Fusion.CovertTransactionSignature.newBuilder()
                                            .setRoundPubkey(ByteString.copyFrom(roundPubKey))
                                            .setTxsignature(ByteString.copyFrom(schnorrSignature.getSignature()))
                                            .setWhichInput(input.getIndex())
                                            .build();
                                    Fusion.CovertMessage covertMessage = Fusion.CovertMessage.newBuilder()
                                            .setSignature(covertTransactionSignature)
                                            .build();
                                    covertSignatureMessages.add(covertMessage);
                                    System.out.println("Signature added.");
                                }
                            }

                            System.out.println("Scheduling signature submission");
                            listener.onFusionStatus(FusionStatus.COVERTLY_SENDING_SIGNATURES);
                            covertSubmitter.scheduleSubmissions(covertSignatureMessages, covertT0 + 20, covertT0 + 30);
                            Fusion.ServerMessage resultServerMessage = this.receiveMessage(20);
                            if(resultServerMessage != null) {
                                Fusion.FusionResult result = resultServerMessage.getFusionresult();
                                if(result.getOk()) {
                                    return FusionStatus.FUSED;
                                } else {
                                    System.out.println("BAD COMPONENTS::");
                                    System.out.println(componentIdxes);
                                    System.out.println(result.getBadComponentsList());
                                    System.out.println(result.getTxsignaturesList());
                                    return FusionStatus.FAILED;
                                }
                            } else {
                                System.out.println("FUSION RESULT NULL");
                                return FusionStatus.FAILED;
                            }
                        } else {
                            System.out.println("SKipping signatures");
                            System.out.println(shareCovertComponentsMsg);
                            return FusionStatus.FAILED;
                        }
                    } else {
                        System.out.println("SHARE COMPONENT MESSAGE: ");
                        System.out.println(shareCovertComponentsServerMsg);
                    }
                } else {
                    System.out.println("ALL COMMITMENT MESSAGE: ");
                    System.out.println(allCommitmentsServerMsg);
                }
            } else {
                System.out.println("ROUND MESSAGE: ");
                System.out.println(blindSigServerMessage);
            }

            return FusionStatus.FAILED;
        }

        return FusionStatus.FAILED;
    }

    private GeneratedComponents genComponents(long numBlanks, ArrayList<Pair<TransactionOutput, ECKey>> inputs, ArrayList<Pair<Script, Long>> outputs, long componentFeeRate) {
        ArrayList<Pair<Fusion.Component.Builder, Long>> components = new ArrayList<>();

        //inputs
        for(Pair<TransactionOutput, ECKey> pair : inputs) {
            long fee = componentFee(sizeOfInput(pair.getRight().getPubKey()), componentFeeRate);
            long value = pair.getLeft().getValue().value;
            Fusion.InputComponent inputComponent = Fusion.InputComponent.newBuilder()
                    .setPrevTxid(ByteString.copyFrom(pair.getLeft().getOutPointFor().getHash().getReversedBytes()))
                    .setPrevIndex((int)pair.getLeft().getOutPointFor().getIndex())
                    .setPubkey(ByteString.copyFrom(pair.getRight().getPubKey()))
                    .setAmount(value)
                    .build();
            Fusion.Component.Builder component = Fusion.Component.newBuilder()
                    .setInput(inputComponent);
            components.add(Pair.of(component, +value-fee));
        }

        //outputs
        for(Pair<Script, Long> pair : outputs) {
            long fee = componentFee(sizeOfOutput(pair.getLeft().getProgram()), componentFeeRate);
            long value = pair.getRight();
            Fusion.OutputComponent outputComponent = Fusion.OutputComponent.newBuilder()
                    .setAmount(value)
                    .setScriptpubkey(ByteString.copyFrom(pair.getLeft().getProgram()))
                    .build();
            Fusion.Component.Builder component = Fusion.Component.newBuilder()
                    .setOutput(outputComponent);
            components.add(Pair.of(component, -value-fee));
        }

        for(int x = 0; x < numBlanks; x++) {
            Fusion.BlankComponent blankComponent = Fusion.BlankComponent.newBuilder()
                    .build();
            Fusion.Component.Builder component = Fusion.Component.newBuilder()
                    .setBlank(blankComponent);
            components.add(Pair.of(component, 0L));
        }

        ArrayList<Component> resultList = new ArrayList<>();
        BigInteger sumNonce = BigInteger.ZERO;
        BigInteger sumAmounts = BigInteger.ZERO;
        //gen commitments
        int cNum = 0;
        for(Pair<Fusion.Component.Builder, Long> pair : components) {
            cNum++;
            long commitAmount = pair.getRight();
            byte[] salt = new SecureRandom().generateSeed(32);
            Fusion.Component modifiedComponent = pair.getLeft().setSaltCommitment(ByteString.copyFrom(Sha256Hash.hash(salt))).build();
            byte[] compSer = modifiedComponent.toByteArray();

            try {
                Pedersen.Commitment commitment = pedersen.commit(commitAmount);
                sumNonce = sumNonce.add(commitment.getNonce());
                sumAmounts = sumAmounts.add(BigInteger.valueOf(commitAmount));

                ECKey ecKey = new ECKey();
                Fusion.InitialCommitment initialCommitment = Fusion.InitialCommitment.newBuilder()
                        .setSaltedComponentHash(ByteString.copyFrom(Sha256Hash.hash(ArrayUtils.addAll(salt, compSer))))
                        .setAmountCommitment(ByteString.copyFrom(commitment.getpUncompressed()))
                        .setCommunicationKey(ByteString.copyFrom(ecKey.getPubKey()))
                        .build();

                byte[] commitSer = initialCommitment.toByteArray();
                ByteBuffer pedersonNonceBuffer = ByteBuffer.allocate(32);
                pedersonNonceBuffer.put(Utils.bigIntegerToBytes(commitment.getNonce(), 32));
                byte[] pedersonNonce = pedersonNonceBuffer.array();
                Fusion.Proof.Builder proofBuilder = Fusion.Proof.newBuilder()
                        .setSalt(ByteString.copyFrom(salt))
                        .setPedersenNonce(ByteString.copyFrom(pedersonNonce));

                resultList.add(new Component(commitSer, cNum, compSer, proofBuilder, ecKey));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        Collections.sort(resultList);

        sumNonce = sumNonce.mod(pedersen.getOrder());
        ByteBuffer pedersonTotalNonceBuffer = ByteBuffer.allocate(32);
        pedersonTotalNonceBuffer.put(Utils.bigIntegerToBytes(sumNonce, 32));
        byte[] pedersenTotalNonce = pedersonTotalNonceBuffer.array();

        return new GeneratedComponents(resultList, sumAmounts, pedersenTotalNonce);
    }

    private long componentFee(long size, long feeRate) {
        return (size * feeRate + 999) / 1000;
    }

    private long sizeOfInput(byte[] pubKey) {
        return 108 + pubKey.length;
    }

    private long sizeOfOutput(byte[] scriptPubKey) {
        return 9 + scriptPubKey.length;
    }

    public double expovariate(Random rng, double lambda) {
        return -Math.log(1.0-rng.nextDouble())/lambda;
    }

    public ArrayList<Double> runningSum(ArrayList<Double> nums) {
        ArrayList<Double> out = new ArrayList<>(nums);
        for (int iElement = 1; iElement < nums.size(); iElement++) {
            out.set(iElement, out.get(iElement - 1) + nums.get(iElement));
        }
        return out;
    }

    public <T> List<List<T>> zip(List<T>... lists) {
        List<List<T>> zipped = new ArrayList<List<T>>();
        for (List<T> list : lists) {
            for (int i = 0, listSize = list.size(); i < listSize; i++) {
                List<T> list2;
                if (i >= zipped.size())
                    zipped.add(list2 = new ArrayList<T>());
                else
                    list2 = zipped.get(i);
                list2.add(list.get(i));
            }
        }
        return zipped;
    }

    public byte[] calcInitialHash(long tier, ByteString covertDomain, int covertPort, boolean covertSsl, long beginTime) throws IOException {
        UnsafeByteArrayOutputStream hashBos = new UnsafeByteArrayOutputStream();
        addToBos(hashBos, "Cash Fusion Session".getBytes());
        addToBos(hashBos, "alpha13".getBytes());
        ByteBuffer tierBuffer = ByteBuffer.allocate(8);
        tierBuffer.putLong(tier);
        byte[] tierBytes = tierBuffer.array();
        addToBos(hashBos, tierBytes);
        addToBos(hashBos, covertDomain.toByteArray());
        ByteBuffer portBuffer = ByteBuffer.allocate(4);
        portBuffer.putInt(covertPort);
        byte[] portBytes = portBuffer.array();
        addToBos(hashBos, portBytes);
        addToBos(hashBos, covertSsl ? Hex.decode("01") : Hex.decode("00"));
        ByteBuffer timeBuffer = ByteBuffer.allocate(8);
        timeBuffer.putLong(beginTime);
        byte[] timeBytes = timeBuffer.array();
        addToBos(hashBos, timeBytes);
        return Sha256Hash.hash(hashBos.toByteArray());
    }

    @SafeVarargs
    public final byte[] calcRoundHash(byte[] lastHash, byte[] roundPubKey, long roundTime, List<ByteString>... lists) throws IOException {
        UnsafeByteArrayOutputStream hashBos = new UnsafeByteArrayOutputStream();
        addToBos(hashBos, "Cash Fusion Round".getBytes());
        addToBos(hashBos, lastHash);
        addToBos(hashBos, roundPubKey);
        ByteBuffer roundTimeBuffer = ByteBuffer.allocate(8);
        roundTimeBuffer.putLong(roundTime);
        byte[] roundTimeBytes = roundTimeBuffer.array();
        addToBos(hashBos, roundTimeBytes);
        for(List<ByteString> list : lists) {
            byte[] listHash = listHash(list);
            addToBos(hashBos, listHash);
        }
        return Sha256Hash.hash(hashBos.toByteArray());
    }

    public byte[] listHash(List<ByteString> list) throws IOException {
        UnsafeByteArrayOutputStream hashBos = new UnsafeByteArrayOutputStream();
        for(ByteString byteString : list) {
            addToBos(hashBos, byteString.toByteArray());
        }
        return Sha256Hash.hash(hashBos.toByteArray());
    }

    public void addToBos(UnsafeByteArrayOutputStream bos, byte[] bytes) throws IOException {
        ByteBuffer sizeBuffer = ByteBuffer.allocate(4); //4 byte prefix with size of next data
        sizeBuffer.putInt(bytes.length);
        bos.write(sizeBuffer.array());
        bos.write(bytes);
    }

    public double covertClock() {
        return (System.currentTimeMillis()/1000D) - covertT0;
    }

    public Transaction constructTransaction(List<ByteString> components, byte[] sessionHash) throws InvalidProtocolBufferException {
        Transaction tx = new Transaction(wallet.getParams());
        tx.setVersion(1);
        tx.setLockTime(0);
        Script opReturnScript = new ScriptBuilder().op(ScriptOpCodes.OP_RETURN)
                .data(Hex.decode("46555a00"))
                .data(sessionHash)
                .build();
        tx.addOutput(Coin.ZERO, opReturnScript);
        for(ByteString compSer : components) {
            Fusion.Component component = Fusion.Component.parseFrom(compSer);
            switch(component.getComponentCase()) {
                case INPUT:
                    Fusion.InputComponent inputComponent = component.getInput();
                    Coin inputAmount = Coin.valueOf(inputComponent.getAmount());
                    byte[] prevOutTxId = Sha256Hash.wrap(inputComponent.getPrevTxid().toByteArray()).getReversedBytes();
                    TransactionOutPoint outpoint = new TransactionOutPoint(wallet.getParams(), inputComponent.getPrevIndex(), Sha256Hash.wrap(prevOutTxId));
                    TransactionInput input = new TransactionInput(wallet.getParams(), null, ScriptBuilder.createEmpty().getProgram(), outpoint, inputAmount);
                    input.setSequenceNumber(0xffffffff);
                    tx.addInput(input);
                    break;
                case OUTPUT:
                    Fusion.OutputComponent outputComponent = component.getOutput();
                    Coin outputAmount = Coin.valueOf(outputComponent.getAmount());
                    Script scriptPubKey = new Script(outputComponent.getScriptpubkey().toByteArray());
                    tx.addOutput(outputAmount, scriptPubKey);
                    break;
                case BLANK:
                    break;
                case COMPONENT_NOT_SET:
                    break;
            }
        }

        System.out.println(tx.toHexString());
        return tx;
    }
}
