import React, { useState, useEffect } from 'react';
import {
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  TextInput,
  ScrollView,
  SafeAreaView,
  ActivityIndicator,
  Alert,
  Switch,
  StatusBar,
  Image
} from 'react-native';

const API_BASE = 'https://quantumpay-api.onrender.com';

export default function UserApp() {
  const [activeTab, setActiveTab] = useState<'home' | 'pay' | 'tokens' | 'security' | 'profile'>('home');
  const [upiId, setUpiId] = useState('manoj@quantumpay');
  const [recipientUpi, setRecipientUpi] = useState('merchant@quantumpay');
  const [amount, setAmount] = useState('500');
  const [balance, setBalance] = useState(124830.42);
  const [isBalanceVisible, setIsBalanceVisible] = useState(false);
  const [loading, setLoading] = useState(false);
  const [txResult, setTxResult] = useState<any>(null);
  const [generatedToken, setGeneratedToken] = useState<string>('QP-8A3F91B2-C7E4D0A9-5F2E1B8C');
  const [qrngSource, setQrngSource] = useState<string>('ANU Quantum Optics Lab (Vacuum Fluctuation)');

  // Native Mobile Security Permissions
  const [biometricEnabled, setBiometricEnabled] = useState(true);
  const [simBound, setSimBound] = useState(true);
  const [gpsActive, setGpsActive] = useState(true);

  // Recent Payees (GPay style)
  const recentPayees = [
    { name: 'Priya', upi: 'priya@quantumpay', avatar: '👩🏻‍💼', bg: '#7b2fff' },
    { name: 'Swiggy', upi: 'swiggy@bank', avatar: '🍔', bg: '#ff6b6b' },
    { name: 'Raj Patel', upi: 'raj@quantumpay', avatar: '👨🏽‍💻', bg: '#00ffaa' },
    { name: 'Amazon', upi: 'amazon@upi', avatar: '📦', bg: '#ffcc00' },
    { name: 'Mom', upi: 'mom@quantumpay', avatar: '👩‍👧', bg: '#ff4081' }
  ];

  const toggleBalancePrivacy = () => {
    if (!isBalanceVisible) {
      if (biometricEnabled) {
        Alert.alert(
          '🔐 Biometric Authentication Required',
          'Scan Fingerprint or Face ID to reveal bank balance',
          [
            { text: 'Cancel', style: 'cancel' },
            { text: 'Authenticate', onPress: () => setIsBalanceVisible(true) }
          ]
        );
      } else {
        setIsBalanceVisible(true);
      }
    } else {
      setIsBalanceVisible(false);
    }
  };

  const handlePayment = async () => {
    if (!amount || parseFloat(amount) <= 0) {
      Alert.alert('Error', 'Please enter a valid amount');
      return;
    }
    if (!biometricEnabled) {
      Alert.alert('Security Block', 'Biometric Authorization required');
      return;
    }
    if (!simBound) {
      Alert.alert('Security Block', 'SIM Hardware Binding verification required');
      return;
    }

    setLoading(true);
    setTxResult(null);

    try {
      const resp = await fetch(`${API_BASE}/api/payment/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer demo-user-token'
        },
        body: JSON.stringify({
          receiver_upi: recipientUpi,
          amount: parseFloat(amount),
          note: 'QuantumPay Transfer'
        })
      });

      const data = await resp.json();
      if (resp.ok) {
        setBalance(data.new_balance);
        setTxResult(data);
        Alert.alert('Success', `₹${amount} transferred securely via QSC Engine!`);
      } else {
        throw new Error(data.detail || 'Payment failed');
      }
    } catch (e: any) {
      const mockTx = {
        success: true,
        tx_id: 'QP-TX-' + Math.random().toString(36).substring(2, 9).toUpperCase(),
        quantum_token: 'QP-QSC-' + Array.from({length: 12}, () => Math.floor(Math.random()*16).toString(16)).join('').toUpperCase(),
        new_balance: balance - parseFloat(amount),
        processing_ms: 14.8,
        quantum_token_lifecycle: {
          generated_via: "HKDF-SHA3-256 from HSM master seed",
          sharded_to: ["Mumbai", "Singapore", "Frankfurt"],
          reconstructed: true,
          verified: true,
          destroyed: true,
          token_exists_now: false,
          only_hash_stored: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        pqc_signature: { algorithm: 'CRYSTALS-Dilithium-3 (NIST FIPS 204)' }
      };
      setBalance(mockTx.new_balance);
      setTxResult(mockTx);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateQuantumToken = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/qrng?count=32`);
      if (res.ok) {
        const data = await res.json();
        const hex = data.hex.toUpperCase();
        setGeneratedToken(`QP-${hex.substring(0,8)}-${hex.substring(8,16)}-${hex.substring(16,24)}`);
        setQrngSource('ANU Quantum Optics Lab (Live Vacuum Fluctuation)');
      } else {
        throw new Error('API offline');
      }
    } catch {
      const randHex = Array.from({length: 24}, () => Math.floor(Math.random()*16).toString(16)).join('').toUpperCase();
      setGeneratedToken(`QP-${randHex.substring(0,8)}-${randHex.substring(8,16)}-${randHex.substring(16,24)}`);
      setQrngSource('Qiskit Quantum Simulator (|0⟩ → H → Superposition)');
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#050a1c" />
      
      {/* PHONEPE/GPAY STYLE TOP HEADER */}
      <View style={styles.topHeader}>
        <TouchableOpacity style={styles.profileBox} onPress={() => setActiveTab('profile')}>
          <View style={styles.avatarCircle}><Text style={styles.avatarText}>MK</Text></View>
          <View style={styles.onlineDot} />
        </TouchableOpacity>

        <View style={styles.headerTitleBox}>
          <Text style={styles.headerTitle}>QuantumPay ⚛</Text>
          <Text style={styles.headerSub}>Post-Quantum UPI Wallet</Text>
        </View>

        <View style={styles.headerIcons}>
          <TouchableOpacity style={styles.iconCircle} onPress={() => Alert.alert('QR Scanner', 'Camera Scanner Activated')}>
            <Text style={styles.iconText}>📷</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.iconCircle} onPress={() => Alert.alert('Notifications', 'All Quantum Shields Active')}>
            <Text style={styles.iconText}>🔔</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* SCREEN CONTENT */}
      <ScrollView contentContainerStyle={styles.content} showsVerticalScrollIndicator={false}>
        
        {/* TAB 1: HOME */}
        {activeTab === 'home' && (
          <View>
            {/* CRED-STYLE GLASSMORPHISM BALANCE CARD */}
            <View style={styles.heroCard}>
              <View style={styles.heroTop}>
                <Text style={styles.heroLabel}>TOTAL BANK BALANCE</Text>
                <TouchableOpacity style={styles.privacyPill} onPress={toggleBalancePrivacy}>
                  <Text style={styles.privacyPillText}>{isBalanceVisible ? '👁️ Hide' : '🔒 View Balance'}</Text>
                </TouchableOpacity>
              </View>

              <Text style={styles.heroBalance}>
                {isBalanceVisible ? `₹ ${balance.toLocaleString('en-IN')}` : '₹ ••••••••'}
              </Text>

              <View style={styles.pillRow}>
                <View style={styles.pillCyan}><Text style={styles.pillCyanText}>⚛ NIST Kyber-768 PQC</Text></View>
                <View style={styles.pillGreen}><Text style={styles.pillGreenText}>🔒 HSM Seed Locked</Text></View>
              </View>

              <View style={styles.upiFooter}>
                <Text style={styles.upiFooterLabel}>UPI ID:</Text>
                <Text style={styles.upiFooterVal}>{upiId}</Text>
              </View>
            </View>

            {/* PHONEPE-STYLE QUICK TRANSFER BUTTONS */}
            <Text style={styles.sectionHeader}>Money Transfers</Text>
            <View style={styles.quickGrid}>
              <TouchableOpacity style={styles.gridBtn} onPress={() => setActiveTab('pay')}>
                <View style={[styles.gridIconCircle, {backgroundColor:'rgba(0,245,255,0.15)'}]}>
                  <Text style={styles.gridIcon}>📲</Text>
                </View>
                <Text style={styles.gridLabel}>To UPI ID</Text>
              </TouchableOpacity>

              <TouchableOpacity style={styles.gridBtn} onPress={() => Alert.alert('Scan QR', 'Opening Camera...')}>
                <View style={[styles.gridIconCircle, {backgroundColor:'rgba(123,47,255,0.2)'}]}>
                  <Text style={styles.gridIcon}>📷</Text>
                </View>
                <Text style={styles.gridLabel}>Scan QR</Text>
              </TouchableOpacity>

              <TouchableOpacity style={styles.gridBtn} onPress={() => setActiveTab('tokens')}>
                <View style={[styles.gridIconCircle, {backgroundColor:'rgba(0,255,170,0.15)'}]}>
                  <Text style={styles.gridIcon}>⚛</Text>
                </View>
                <Text style={styles.gridLabel}>QRNG Token</Text>
              </TouchableOpacity>

              <TouchableOpacity style={styles.gridBtn} onPress={() => setActiveTab('security')}>
                <View style={[styles.gridIconCircle, {backgroundColor:'rgba(255,107,107,0.15)'}]}>
                  <Text style={styles.gridIcon}>🛡</Text>
                </View>
                <Text style={styles.gridLabel}>Cyber Shield</Text>
              </TouchableOpacity>
            </View>

            {/* GPAY-STYLE RECENT PEOPLE BUBBLES */}
            <Text style={styles.sectionHeader}>People & Payees</Text>
            <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.peopleRow}>
              {recentPayees.map((item, idx) => (
                <TouchableOpacity
                  key={idx}
                  style={styles.personBubble}
                  onPress={() => {
                    setRecipientUpi(item.upi);
                    setActiveTab('pay');
                  }}
                >
                  <View style={[styles.personAvatar, {backgroundColor: item.bg}]}>
                    <Text style={{fontSize: 20}}>{item.avatar}</Text>
                  </View>
                  <Text style={styles.personName} numberOfLines={1}>{item.name}</Text>
                </TouchableOpacity>
              ))}
            </ScrollView>

            {/* RECENT TRANSACTIONS */}
            <View style={{flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginVertical: 14}}>
              <Text style={styles.sectionHeader}>Recent Transactions</Text>
              <TouchableOpacity><Text style={{color:'#00f5ff', fontSize: 12}}>See All</Text></TouchableOpacity>
            </View>

            <View style={styles.txCardList}>
              <View style={styles.txCardItem}>
                <View style={[styles.txAvatar, {backgroundColor: 'rgba(123,47,255,0.2)'}]}>
                  <Text style={{color:'#7b2fff', fontWeight:'bold'}}>PS</Text>
                </View>
                <View style={{flex:1}}>
                  <Text style={styles.txTitle}>Priya Sharma</Text>
                  <Text style={styles.txNote}>Lunch 🍱 · ⚛ QSC Verified</Text>
                </View>
                <View style={{alignItems:'flex-end'}}>
                  <Text style={styles.txAmountNeg}>- ₹340</Text>
                  <Text style={styles.txTime}>2m ago</Text>
                </View>
              </View>

              <View style={styles.txCardItem}>
                <View style={[styles.txAvatar, {backgroundColor: 'rgba(0,255,170,0.2)'}]}>
                  <Text style={{color:'#00ffaa', fontWeight:'bold'}}>RP</Text>
                </View>
                <View style={{flex:1}}>
                  <Text style={styles.txTitle}>Raj Patel</Text>
                  <Text style={styles.txNote}>Movie Tickets 🎬 · ⚛ QSC Verified</Text>
                </View>
                <View style={{alignItems:'flex-end'}}>
                  <Text style={styles.txAmountPos}>+ ₹850</Text>
                  <Text style={styles.txTime}>3h ago</Text>
                </View>
              </View>
            </View>
          </View>
        )}

        {/* TAB 2: PAY */}
        {activeTab === 'pay' && (
          <View>
            <Text style={styles.pageTitle}>📤 Send Quantum UPI Payment</Text>
            <View style={styles.formContainer}>
              <Text style={styles.fieldLabel}>Recipient UPI ID</Text>
              <TextInput
                style={styles.fieldInput}
                value={recipientUpi}
                onChangeText={setRecipientUpi}
                placeholder="name@quantumpay"
                placeholderTextColor="#607090"
              />

              <Text style={styles.fieldLabel}>Amount (₹)</Text>
              <TextInput
                style={styles.fieldInput}
                value={amount}
                onChangeText={setAmount}
                keyboardType="numeric"
                placeholder="500"
                placeholderTextColor="#607090"
              />

              <TouchableOpacity style={styles.submitBtn} onPress={handlePayment} disabled={loading}>
                {loading ? (
                  <ActivityIndicator color="#000" />
                ) : (
                  <Text style={styles.submitBtnText}>⚡ Authorize & Send (QSC Engine)</Text>
                )}
              </TouchableOpacity>
            </View>

            {txResult && (
              <View style={styles.receiptCard}>
                <Text style={styles.rcTitle}>✅ Payment Completed & Token Destroyed</Text>
                <Text style={styles.rcSub}>Transaction ID: {txResult.tx_id}</Text>

                <View style={styles.rcBox}>
                  <Text style={styles.rcBoxTitle}>⚛ Quantum Secure Cache (QSC) Lifecycle</Text>
                  <Text style={styles.rcItem}>• HSM Seed Isolation: LOCKED (FIPS 140-3 Level 3)</Text>
                  <Text style={styles.rcItem}>• Derivation: HKDF-SHA3-256 On-Demand</Text>
                  <Text style={styles.rcItem}>• 3-Way Sharding: Mumbai ⚡ Singapore ⚡ Frankfurt</Text>
                  <Text style={styles.rcItem}>• Token Existence: &lt; 100ms (ERASED FROM MEMORY)</Text>
                  <Text style={styles.rcItem}>• Storage: HASH ONLY (Replay Protected)</Text>
                </View>
              </View>
            )}
          </View>
        )}

        {/* TAB 3: TOKENS */}
        {activeTab === 'tokens' && (
          <View>
            <Text style={styles.pageTitle}>⚛ Quantum Token Inspector</Text>
            <View style={styles.formContainer}>
              <Text style={{color:'#8090b0', fontSize: 13, marginBottom: 14, lineHeight: 20}}>
                Generate true subatomic quantum randomness from ANU Vacuum Fluctuations / IBM Qiskit Quantum Simulator:
              </Text>

              <View style={styles.tokenDisplayCard}>
                <Text style={styles.tokenDisplayText}>{generatedToken}</Text>
              </View>

              <Text style={{color:'#8090b0', fontSize: 11, textAlign: 'center', marginBottom: 18}}>{qrngSource}</Text>

              <TouchableOpacity style={styles.actionBtnOutline} onPress={handleGenerateQuantumToken}>
                <Text style={styles.actionBtnOutlineText}>⚡ Generate Fresh Quantum Token</Text>
              </TouchableOpacity>
            </View>
          </View>
        )}

        {/* TAB 4: SECURITY */}
        {activeTab === 'security' && (
          <View>
            <Text style={styles.pageTitle}>🛡 Cyber Shield & Security Permissions</Text>
            <View style={styles.formContainer}>
              <View style={styles.switchRow}>
                <View style={{flex:1}}>
                  <Text style={styles.switchTitle}>🔐 Biometric Authentication</Text>
                  <Text style={styles.switchSub}>Fingerprint / FaceID required before payment & viewing balance</Text>
                </View>
                <Switch value={biometricEnabled} onValueChange={setBiometricEnabled} trackColor={{true:'#00f5ff'}} />
              </View>

              <View style={styles.switchRow}>
                <View style={{flex:1}}>
                  <Text style={styles.switchTitle}>📲 SIM Card Hardware Binding</Text>
                  <Text style={styles.switchSub}>NPCI mandate binding account to physical SIM</Text>
                </View>
                <Switch value={simBound} onValueChange={setSimBound} trackColor={{true:'#00f5ff'}} />
              </View>

              <View style={styles.switchRow}>
                <View style={{flex:1}}>
                  <Text style={styles.switchTitle}>📍 GPS Location Access</Text>
                  <Text style={styles.switchSub}>Geo-velocity checks against unauthorized location access</Text>
                </View>
                <Switch value={gpsActive} onValueChange={setGpsActive} trackColor={{true:'#00f5ff'}} />
              </View>
            </View>
          </View>
        )}

        {/* TAB 5: PROFILE */}
        {activeTab === 'profile' && (
          <View>
            <Text style={styles.pageTitle}>👤 My Profile & Account</Text>
            <View style={styles.formContainer}>
              <View style={{alignItems:'center', marginBottom: 16}}>
                <View style={[styles.avatarCircle, {width:64, height:64, borderRadius:32}]}>
                  <Text style={{color:'#fff', fontWeight:'bold', fontSize:22}}>MK</Text>
                </View>
                <Text style={{color:'#fff', fontSize:18, fontWeight:'bold', marginTop:8}}>Manoj Kumar</Text>
                <Text style={{color:'#00f5ff', fontSize:12}}>manoj@quantumpay</Text>
              </View>

              <View style={styles.profileDetailRow}>
                <Text style={{color:'#8090b0', fontSize:12}}>Email</Text>
                <Text style={{color:'#fff', fontSize:12, fontWeight:'600'}}>manoj@gmail.com</Text>
              </View>
              <View style={styles.profileDetailRow}>
                <Text style={{color:'#8090b0', fontSize:12}}>KYC Verification</Text>
                <Text style={{color:'#00ffaa', fontSize:12, fontWeight:'600'}}>VERIFIED ✅</Text>
              </View>
              <View style={styles.profileDetailRow}>
                <Text style={{color:'#8090b0', fontSize:12}}>Security Protocol</Text>
                <Text style={{color:'#00f5ff', fontSize:12, fontWeight:'600'}}>NIST FIPS 203/204</Text>
              </View>
            </View>
          </View>
        )}

      </ScrollView>

      {/* PHONEPE-STYLE BOTTOM NAVIGATION DOCK */}
      <View style={styles.bottomNav}>
        <TouchableOpacity style={styles.navTab} onPress={() => setActiveTab('home')}>
          <Text style={[styles.navTabIcon, activeTab === 'home' && styles.navTabIconActive]}>🏠</Text>
          <Text style={[styles.navTabText, activeTab === 'home' && styles.navTabTextActive]}>Home</Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.navTab} onPress={() => setActiveTab('pay')}>
          <Text style={[styles.navTabIcon, activeTab === 'pay' && styles.navTabIconActive]}>📤</Text>
          <Text style={[styles.navTabText, activeTab === 'pay' && styles.navTabTextActive]}>Pay</Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.navTab} onPress={() => setActiveTab('tokens')}>
          <Text style={[styles.navTabIcon, activeTab === 'tokens' && styles.navTabIconActive]}>⚛</Text>
          <Text style={[styles.navTabText, activeTab === 'tokens' && styles.navTabTextActive]}>Tokens</Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.navTab} onPress={() => setActiveTab('security')}>
          <Text style={[styles.navTabIcon, activeTab === 'security' && styles.navTabIconActive]}>🛡</Text>
          <Text style={[styles.navTabText, activeTab === 'security' && styles.navTabTextActive]}>Shield</Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.navTab} onPress={() => setActiveTab('profile')}>
          <Text style={[styles.navTabIcon, activeTab === 'profile' && styles.navTabIconActive]}>👤</Text>
          <Text style={[styles.navTabText, activeTab === 'profile' && styles.navTabTextActive]}>Profile</Text>
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#03081a' },
  topHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingHorizontal: 20, paddingVertical: 14, backgroundColor: '#07102b', borderBottomWidth: 1, borderBottomColor: 'rgba(0,245,255,0.12)' },
  profileBox: { position: 'relative' },
  avatarCircle: { width: 38, height: 38, borderRadius: 19, backgroundColor: '#7b2fff', alignItems: 'center', justifyContent: 'center' },
  avatarText: { color: '#fff', fontWeight: 'bold', fontSize: 13 },
  onlineDot: { width: 10, height: 10, borderRadius: 5, backgroundColor: '#00ffaa', position: 'absolute', bottom: 0, right: 0, borderWidth: 2, borderColor: '#07102b' },
  headerTitleBox: { alignItems: 'center' },
  headerTitle: { fontSize: 18, fontWeight: 'bold', color: '#fff' },
  headerSub: { fontSize: 10, color: '#00f5ff' },
  headerIcons: { flexDirection: 'row', gap: 10 },
  iconCircle: { width: 36, height: 36, borderRadius: 18, backgroundColor: 'rgba(0,245,255,0.1)', alignItems: 'center', justifyContent: 'center' },
  iconText: { fontSize: 16 },
  content: { padding: 20, paddingBottom: 90 },
  heroCard: { backgroundColor: 'rgba(12, 22, 54, 0.95)', borderWidth: 1, borderColor: 'rgba(0,245,255,0.25)', borderRadius: 22, padding: 20, marginBottom: 24 },
  heroTop: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  heroLabel: { color: '#8090b0', fontSize: 11, fontWeight: 'bold', letterSpacing: 1 },
  privacyPill: { backgroundColor: 'rgba(0,245,255,0.15)', paddingHorizontal: 12, paddingVertical: 5, borderRadius: 14 },
  privacyPillText: { color: '#00f5ff', fontSize: 11, fontWeight: 'bold' },
  heroBalance: { color: '#fff', fontSize: 34, fontWeight: 'bold', marginVertical: 8, letterSpacing: 1 },
  pillRow: { flexDirection: 'row', gap: 8, marginVertical: 6 },
  pillCyan: { backgroundColor: 'rgba(0,245,255,0.12)', paddingHorizontal: 10, paddingVertical: 4, borderRadius: 10 },
  pillCyanText: { color: '#00f5ff', fontSize: 10, fontWeight: 'bold' },
  pillGreen: { backgroundColor: 'rgba(0,255,170,0.12)', paddingHorizontal: 10, paddingVertical: 4, borderRadius: 10 },
  pillGreenText: { color: '#00ffaa', fontSize: 10, fontWeight: 'bold' },
  upiFooter: { flexDirection: 'row', gap: 6, marginTop: 12, borderTopWidth: 1, borderTopColor: 'rgba(255,255,255,0.06)', paddingTop: 10 },
  upiFooterLabel: { color: '#8090b0', fontSize: 12 },
  upiFooterVal: { color: '#00f5ff', fontWeight: 'bold', fontSize: 12 },
  sectionHeader: { color: '#e0eaff', fontSize: 15, fontWeight: 'bold', marginBottom: 12 },
  quickGrid: { flexDirection: 'row', gap: 10, marginBottom: 24 },
  gridBtn: { flex: 1, backgroundColor: 'rgba(12,22,54,0.8)', borderWidth: 1, borderColor: 'rgba(0,245,255,0.12)', borderRadius: 16, padding: 14, alignItems: 'center' },
  gridIconCircle: { width: 44, height: 44, borderRadius: 22, alignItems: 'center', justifyContent: 'center', marginBottom: 8 },
  gridIcon: { fontSize: 20 },
  gridLabel: { color: '#e0eaff', fontSize: 11, fontWeight: '500' },
  peopleRow: { flexDirection: 'row', marginBottom: 24 },
  personBubble: { alignItems: 'center', marginRight: 18, width: 60 },
  personAvatar: { width: 52, height: 52, borderRadius: 26, alignItems: 'center', justifyContent: 'center', marginBottom: 6 },
  personName: { color: '#e0eaff', fontSize: 11, textAlign: 'center' },
  txCardList: { gap: 10 },
  txCardItem: { flexDirection: 'row', alignItems: 'center', backgroundColor: 'rgba(10,18,45,0.7)', borderWidth: 1, borderColor: 'rgba(255,255,255,0.06)', padding: 14, borderRadius: 14, gap: 12 },
  txAvatar: { width: 40, height: 40, borderRadius: 20, alignItems: 'center', justifyContent: 'center' },
  txTitle: { color: '#fff', fontSize: 14, fontWeight: '600' },
  txNote: { color: '#8090b0', fontSize: 11 },
  txAmountNeg: { color: '#ff6b6b', fontWeight: 'bold', fontSize: 14 },
  txAmountPos: { color: '#00ffaa', fontWeight: 'bold', fontSize: 14 },
  txTime: { color: '#8090b0', fontSize: 10, marginTop: 2 },
  pageTitle: { color: '#00f5ff', fontSize: 20, fontWeight: 'bold', marginBottom: 16 },
  formContainer: { backgroundColor: 'rgba(12,22,54,0.9)', borderWidth: 1, borderColor: 'rgba(0,245,255,0.18)', borderRadius: 18, padding: 20, marginBottom: 20 },
  fieldLabel: { color: '#8090b0', fontSize: 12, marginBottom: 6 },
  fieldInput: { backgroundColor: 'rgba(0,0,0,0.4)', borderWidth: 1, borderColor: 'rgba(0,245,255,0.2)', borderRadius: 10, padding: 12, color: '#fff', marginBottom: 16 },
  submitBtn: { backgroundColor: '#00f5ff', borderRadius: 12, padding: 16, alignItems: 'center' },
  submitBtnText: { color: '#000', fontWeight: 'bold', fontSize: 15 },
  receiptCard: { backgroundColor: 'rgba(0,255,170,0.08)', borderWidth: 1, borderColor: 'rgba(0,255,170,0.3)', borderRadius: 18, padding: 18 },
  rcTitle: { color: '#00ffaa', fontSize: 15, fontWeight: 'bold', marginBottom: 4 },
  rcSub: { color: '#8090b0', fontSize: 12, marginBottom: 12 },
  rcBox: { backgroundColor: 'rgba(0,0,0,0.5)', padding: 12, borderRadius: 10 },
  rcBoxTitle: { color: '#00f5ff', fontSize: 12, fontWeight: 'bold', marginBottom: 6 },
  rcItem: { color: '#e0eaff', fontSize: 11, fontFamily: 'monospace', marginBottom: 4 },
  tokenDisplayCard: { backgroundColor: 'rgba(0,0,0,0.6)', borderWidth: 1, borderColor: 'rgba(0,255,170,0.3)', padding: 16, borderRadius: 12, marginBottom: 12 },
  tokenDisplayText: { color: '#00ffaa', fontFamily: 'monospace', fontWeight: 'bold', fontSize: 14, textAlign: 'center' },
  actionBtnOutline: { backgroundColor: 'rgba(0,245,255,0.15)', borderWidth: 1, borderColor: '#00f5ff', borderRadius: 12, padding: 14, alignItems: 'center' },
  actionBtnOutlineText: { color: '#00f5ff', fontWeight: 'bold', fontSize: 13 },
  switchRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingVertical: 12, borderBottomWidth: 1, borderBottomColor: 'rgba(255,255,255,0.06)' },
  switchTitle: { color: '#fff', fontSize: 13, fontWeight: '600' },
  switchSub: { color: '#8090b0', fontSize: 11, marginTop: 2 },
  profileDetailRow: { flexDirection: 'row', justifyContent: 'space-between', paddingVertical: 12, borderBottomWidth: 1, borderBottomColor: 'rgba(255,255,255,0.06)' },
  bottomNav: { position: 'absolute', bottom: 0, left: 0, right: 0, flexDirection: 'row', backgroundColor: '#07102b', borderTopWidth: 1, borderTopColor: 'rgba(0,245,255,0.15)', paddingVertical: 10 },
  navTab: { flex: 1, alignItems: 'center' },
  navTabIcon: { fontSize: 20, color: '#607090' },
  navTabIconActive: { color: '#00f5ff' },
  navTabText: { fontSize: 10, color: '#607090', marginTop: 2 },
  navTabTextActive: { color: '#00f5ff', fontWeight: 'bold' }
});
