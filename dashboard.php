<?php
include 'config.php';

// In your dashboard.php, update the unban action:
if (isset($_GET['unban'])) {
    $ip = $conn->real_escape_string($_GET['unban']);
    
    // Remove from banned_ips table
    $conn->query("DELETE FROM banned_ips WHERE ip_address='$ip'");
    
    // Also reset the failure count
    $conn->query("DELETE FROM ip_failures WHERE ip_address='$ip'");
    
    // Force immediate refresh by adding timestamp
    header("Location: dashboard.php?refreshed=" . time());
    exit();
}

if (isset($_GET['unban_all'])) {
    $conn->query("DELETE FROM banned_ips");
    $conn->query("DELETE FROM ip_failures");
    header("Location: dashboard.php");
    exit();
}

if (isset($_GET['clear_history'])) {
    $conn->query("DELETE FROM attacks");
    header("Location: dashboard.php");
    exit();
}

// Get statistics
$stats = [];
$result = $conn->query("SELECT COUNT(*) as total FROM attacks");
$stats['total_attempts'] = $result->fetch_assoc()['total'];

$result = $conn->query("SELECT COUNT(DISTINCT ip_address) as unique_ips FROM attacks");
$stats['unique_ips'] = $result->fetch_assoc()['unique_ips'];

$result = $conn->query("SELECT protocol, COUNT(*) as count FROM attacks GROUP BY protocol");
$stats['protocols'] = $result->fetch_all(MYSQLI_ASSOC);

// Get recent attacks
$recent_attacks = $conn->query("SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 20");
$banned_ips = $conn->query("SELECT * FROM banned_ips ORDER BY banned_at DESC");

// Get failure statistics
$failure_stats = $conn->query("
    SELECT ip_address, failure_count, last_failure 
    FROM ip_failures 
    ORDER BY failure_count DESC
");

// Get attack statistics for IP monitoring
$ip_stats = $conn->query("
    SELECT ip_address, COUNT(*) as attempt_count, 
           MAX(timestamp) as last_attempt,
           GROUP_CONCAT(DISTINCT protocol) as protocols
    FROM attacks 
    GROUP BY ip_address 
    ORDER BY attempt_count DESC
");
?>
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f4f4f4; }
        .header { background: #2c3e50; color: white; padding: 20px; text-align: center; border-radius: 5px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-box { background: white; padding: 20px; border-radius: 5px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .section { background: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #2c3e50; color: white; }
        .btn { background: #e74c3c; color: white; padding: 8px 15px; text-decoration: none; border-radius: 3px; margin: 2px; display: inline-block; }
        .btn-green { background: #27ae60; }
        .btn-blue { background: #3498db; }
        .btn-orange { background: #f39c12; }
        .ip-monitor { background: #f8f9fa; padding: 10px; margin: 5px 0; border-radius: 3px; }
        .banned { color: #e74c3c; font-weight: bold; }
        .warning { color: #f39c12; font-weight: bold; }
        .safe { color: #27ae60; }
        .action-buttons { margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🐝 Honeypot Security Dashboard</h1>
        <p>Real-time attack monitoring system</p>
    </div>

    <div class="action-buttons">
        <a href="?clear_history=1" class="btn" onclick="return confirm('Clear all attack history?')">🗑️ Clear Attack History</a>
        <a href="?unban_all=1" class="btn btn-blue" onclick="return confirm('Unban ALL IP addresses and reset all failure counts?')">🔓 Unban All IPs</a>
    </div>

    <div class="stats">
        <div class="stat-box">
            <h3><?php echo $stats['total_attempts']; ?></h3>
            <p>Total Attacks</p>
        </div>
        <div class="stat-box">
            <h3><?php echo $stats['unique_ips']; ?></h3>
            <p>Unique IPs</p>
        </div>
        <?php foreach ($stats['protocols'] as $protocol): ?>
        <div class="stat-box">
            <h3><?php echo $protocol['count']; ?></h3>
            <p><?php echo $protocol['protocol']; ?> Attacks</p>
        </div>
        <?php endforeach; ?>
    </div>

  
    <div class="section">
        <h2>📋 Recent Attack Attempts</h2>
        <table>
            <tr>
                <th>Time</th>
                <th>IP Address</th>
                <th>Username</th>
                <th>Password</th>
                <th>Protocol</th>
            </tr>
            <?php while($attack = $recent_attacks->fetch_assoc()): ?>
            <tr>
                <td><?php echo $attack['timestamp']; ?></td>
                <td><?php echo $attack['ip_address']; ?></td>
                <td><?php echo htmlspecialchars($attack['username']); ?></td>
                <td><?php echo htmlspecialchars($attack['password']); ?></td>
                <td><?php echo $attack['protocol']; ?></td>
            </tr>
            <?php endwhile; ?>
        </table>
    </div>

    <div class="section">
        <h2>🚫 Banned IP Addresses</h2>
        <table>
            <tr>
                <th>IP Address</th>
                <th>Reason</th>
                <th>Banned At</th>
                <th>Actions</th>
            </tr>
            <?php while($ip = $banned_ips->fetch_assoc()): ?>
            <tr>
                <td class="banned"><?php echo $ip['ip_address']; ?></td>
                <td><?php echo $ip['reason']; ?></td>
                <td><?php echo $ip['banned_at']; ?></td>
                <td>
                    <a href="?unban=<?php echo $ip['ip_address']; ?>" class="btn btn-green" onclick="return confirm('Unban <?php echo $ip['ip_address']; ?>?')">Unban</a>
                </td>
            </tr>
            <?php endwhile; ?>
        </table>
    </div>
</body>
</html>
