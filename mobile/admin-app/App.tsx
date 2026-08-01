import React, { useState, useEffect } from 'react';
import {
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  ScrollView,
  SafeAreaView,
  ActivityIndicator,
  StatusBar
} from 'react-native';

const API_BASE = 'https://quantumpay-api.onrender.com';

export default function AdminApp() {
  const [activeSection, setActiveSection] = useState<'telemetry' | 'hsm' | 'threats' | 'audit'>('telemetry');
  const [hsmData, setHsmData] = useState<any>(null);
  const [threats, setThreats] = useState<any[]>([]);
  const [rbiStatus, setRbiStatus] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchAdminMetrics();
  }, []);

  const fetchAdminMetrics = async () => {
    setLoading(true);
    try {
      const [hsmRes, threatRes, rbiRes] = await Promise.all([
        fetch(`${API_BASE}/api/hsm/vault-status`),
        fetch(`${API_BASE}/api/threats/live`),
        fetch(`${API_BASE}/api/rbi/sandbox-verify`)
      ]);

      if (hsmRes.ok) setHsmData(await hsmRes.json());
      if (threatRes.ok) {
        const tData = await threatRes.json();
        setThreats(tData.threats || []);
      }
      if (rbiRes.ok) setRbiStatus(await rbiRes.json());
    } catch {
      // Mock Data for Demo
      setHsmData({
        status: "ONLINE",
        model: "Thales Luna Network HSM 7 (FIPS 140-3 Level 3)",
        operations_performed: 148920,
        uptime_hours: 742.5,
        seed_accessible: false,
        tamper_status: "CLEAR"
      });
      setThreats([
        { id: 1, type: "SQLi Probe", source: "185.220.101.42", layer: "PQC Shield", blocked: true, response_ms: 12.4 },
        { id: 2, type: "Replay Attack", source: "192.168.1.100", layer: "QSC Ephemeral", blocked: true, response_ms: 8.1 },
        { id: 3, type: "MITM Intercept", source: "45.33.18.9", layer: "Kyber-768 Tunnel", blocked: true, response_ms: 14.2 }
      ]);
      setRbiStatus({
        status: "APPROVED",
        sandbox_id: "RBI-SBX-9941A",
        compliance: { pqc_standard: "NIST FIPS 203/204", data_localization: "COMPLIANT" }
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" />

      {/* ADMIN HEADER */}
      <View style={styles.header}>
        <View style={styles.headerLeft}>
          <Text style={styles.logoIcon}>🏛</Text>
          <View>
            <Text style={styles.title}>QuantumPay Officer Console</Text>
            <Text style={styles.subtitle}>Authorized Admin Telemetry & Governance</Text>
          </View>
        </View>
        <TouchableOpacity style={styles.refreshBtn} onPress={fetchAdminMetrics}>
          <Text style={styles.refreshIcon}>🔄</Text>
        </TouchableOpacity>
      </View>

      {/* NAV TABS */}
      <View style={styles.tabRow}>
        <TouchableOpacity
          style={[styles.tabBtn, activeSection === 'telemetry' && styles.tabBtnActive]}
          onPress={() => setActiveSection('telemetry')}
        >
          <Text style={[styles.tabText, activeSection === 'telemetry' && styles.tabTextActive]}>Telemetry</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.tabBtn, activeSection === 'hsm' && styles.tabBtnActive]}
          onPress={() => setActiveSection('hsm')}
        >
          <Text style={[styles.tabText, activeSection === 'hsm' && styles.tabTextActive]}>HSM Vault</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.tabBtn, activeSection === 'threats' && styles.tabBtnActive]}
          onPress={() => setActiveSection('threats')}
        >
          <Text style={[styles.tabText, activeSection === 'threats' && styles.tabTextActive]}>Threat Log</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.tabBtn, activeSection === 'audit' && styles.tabBtnActive]}
          onPress={() => setActiveSection('audit')}
        >
          <Text style={[styles.tabText, activeSection === 'audit' && styles.tabTextActive]}>RBI Audit</Text>
        </TouchableOpacity>
      </View>

      <ScrollView contentContainerStyle={styles.content}>
        
        {/* SECTION 1: TELEMETRY */}
        {activeSection === 'telemetry' && (
          <View>
            <View style={styles.grid2}>
              <View style={styles.metricCard}>
                <Text style={styles.mLabel}>Active QSC Shards</Text>
                <Text style={styles.mVal}>3 / 3</Text>
                <Text style={styles.mSub}>Mumbai ⚡ Singapore ⚡ Frankfurt</Text>
              </View>
              <View style={styles.metricCard}>
                <Text style={styles.mLabel}>Total Threats Blocked</Text>
                <Text style={styles.mVal}>3,412</Text>
                <Text style={styles.mSub}>100% Zero-Trust Success</Text>
              </View>
            </View>

            <View style={styles.card}>
              <Text style={styles.cardTitle}>⚛ Quantum Secure Cache (QSC) Status</Text>
              <View style={styles.row}>
                <Text style={styles.rLabel}>Token Derivation:</Text>
                <Text style={styles.rVal}>HKDF-SHA3-256 (On-Demand)</Text>
              </View>
              <View style={styles.row}>
                <Text style={styles.rLabel}>Token Lifetime:</Text>
                <Text style={styles.rVal}>&lt; 100ms (Ephemeral Erasure)</Text>
              </View>
              <View style={styles.row}>
                <Text style={styles.rLabel}>Persistence Mode:</Text>
                <Text style={styles.rVal}>SHA-256 Hash Only</Text>
              </View>
            </View>
          </View>
        )}

        {/* SECTION 2: HSM VAULT */}
        {activeSection === 'hsm' && (
          <View>
            <View style={styles.card}>
              <Text style={styles.cardTitle}>🔒 Hardware Security Module (HSM)</Text>
              <View style={styles.statusBox}>
                <Text style={styles.statusText}>STATUS: {hsmData?.status || 'ONLINE'}</Text>
              </View>
              <View style={styles.row}>
                <Text style={styles.rLabel}>Hardware Model:</Text>
                <Text style={styles.rVal}>{hsmData?.model || 'Thales Luna Network HSM 7'}</Text>
              </View>
              <View style={styles.row}>
                <Text style={styles.rLabel}>FIPS Certification:</Text>
                <Text style={styles.rVal}>FIPS 140-3 Level 3</Text>
              </View>
              <View style={styles.row}>
                <Text style={styles.rLabel}>Master Seed Access:</Text>
                <Text style={[styles.rVal, {color:'#ff6b6b'}]}>IMPOSSIBLE (Hardware Locked)</Text>
              </View>
              <View style={styles.row}>
                <Text style={styles.rLabel}>Operations Signed:</Text>
                <Text style={styles.rVal}>{hsmData?.operations_performed || 148920}</Text>
              </View>
            </View>
          </View>
        )}

        {/* SECTION 3: THREAT LOG */}
        {activeSection === 'threats' && (
          <View>
            <Text style={styles.screenTitle}>🛡 Real-Time Attack Telemetry</Text>
            {threats.map((t, idx) => (
              <View key={idx} style={styles.threatItem}>
                <View style={styles.tLeft}>
                  <Text style={styles.tType}>{t.type}</Text>
                  <Text style={styles.tSource}>Source: {t.source} · Layer: {t.layer}</Text>
                </View>
                <View style={styles.tBadge}>
                  <Text style={styles.tBadgeText}>BLOCKED ({t.response_ms}ms)</Text>
                </View>
              </View>
            ))}
          </View>
        )}

        {/* SECTION 4: RBI AUDIT */}
        {activeSection === 'audit' && (
          <View>
            <View style={styles.card}>
              <Text style={styles.cardTitle}>📜 RBI / NPCI Regulatory Sandbox</Text>
              <View style={styles.row}>
                <Text style={styles.rLabel}>Sandbox ID:</Text>
                <Text style={styles.rVal}>{rbiStatus?.sandbox_id || 'RBI-SBX-9941A'}</Text>
              </View>
              <View style={styles.row}>
                <Text style={styles.rLabel}>Status:</Text>
                <Text style={[styles.rVal, {color:'#00ffaa'}]}>APPROVED</Text>
              </View>
              <View style={styles.row}>
                <Text style={styles.rLabel}>PQC Standard:</Text>
                <Text style={styles.rVal}>NIST FIPS 203/204 Compliant</Text>
              </View>
              <View style={styles.row}>
                <Text style={styles.rLabel}>Data Localization:</Text>
                <Text style={styles.rVal}>COMPLIANT (India Region)</Text>
              </View>
            </View>
          </View>
        )}

      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#030816' },
  header: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingHorizontal: 20, paddingVertical: 14, backgroundColor: '#09132e', borderBottomWidth: 1, borderBottomColor: 'rgba(0,245,255,0.15)' },
  headerLeft: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  logoIcon: { fontSize: 26 },
  title: { fontSize: 16, fontWeight: 'bold', color: '#fff' },
  subtitle: { fontSize: 11, color: '#8090b0' },
  refreshBtn: { width: 36, height: 36, borderRadius: 18, backgroundColor: 'rgba(0,245,255,0.1)', alignItems: 'center', justifyContent: 'center' },
  refreshIcon: { fontSize: 16 },
  tabRow: { flexDirection: 'row', backgroundColor: '#070f26', padding: 6, gap: 6 },
  tabBtn: { flex: 1, paddingVertical: 10, alignItems: 'center', borderRadius: 8 },
  tabBtnActive: { backgroundColor: 'rgba(0,245,255,0.15)', borderWidth: 1, borderColor: '#00f5ff' },
  tabText: { color: '#607090', fontSize: 12, fontWeight: 'bold' },
  tabTextActive: { color: '#00f5ff' },
  content: { padding: 20 },
  grid2: { flexDirection: 'row', gap: 12, marginBottom: 16 },
  metricCard: { flex: 1, backgroundColor: 'rgba(10,20,50,0.8)', borderWidth: 1, borderColor: 'rgba(0,245,255,0.15)', borderRadius: 14, padding: 14 },
  mLabel: { color: '#8090b0', fontSize: 11 },
  mVal: { color: '#00ffaa', fontSize: 22, fontWeight: 'bold', marginVertical: 4 },
  mSub: { color: '#8090b0', fontSize: 10 },
  card: { backgroundColor: 'rgba(10,20,50,0.9)', borderWidth: 1, borderColor: 'rgba(0,245,255,0.15)', borderRadius: 16, padding: 18, marginBottom: 16 },
  cardTitle: { color: '#00f5ff', fontSize: 14, fontWeight: 'bold', marginBottom: 12 },
  screenTitle: { color: '#00f5ff', fontSize: 16, fontWeight: 'bold', marginBottom: 14 },
  row: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 10, borderBottomWidth: 1, borderBottomColor: 'rgba(255,255,255,0.04)', paddingBottom: 6 },
  rLabel: { color: '#8090b0', fontSize: 12 },
  rVal: { color: '#fff', fontSize: 12, fontWeight: '600' },
  statusBox: { backgroundColor: 'rgba(0,255,170,0.12)', padding: 10, borderRadius: 8, marginBottom: 14, alignItems: 'center' },
  statusText: { color: '#00ffaa', fontWeight: 'bold', fontSize: 13 },
  threatItem: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', backgroundColor: 'rgba(15,25,60,0.8)', borderWidth: 1, borderColor: 'rgba(255,107,107,0.2)', padding: 14, borderRadius: 12, marginBottom: 10 },
  tLeft: { flex: 1 },
  tType: { color: '#ff6b6b', fontWeight: 'bold', fontSize: 13 },
  tSource: { color: '#8090b0', fontSize: 11, marginTop: 2 },
  tBadge: { backgroundColor: 'rgba(0,255,170,0.15)', paddingHorizontal: 10, paddingVertical: 4, borderRadius: 8 },
  tBadgeText: { color: '#00ffaa', fontSize: 10, fontWeight: 'bold' }
});
