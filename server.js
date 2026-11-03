const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Phục vụ thư mục public chứa file giao diện index.html
const publicPath = path.resolve(__dirname, 'public');
app.use(express.static(publicPath));

// Cấu hình tài khoản đăng nhập Admin
const ADMIN_USER = "hson";
const ADMIN_PASS = "Son2012@";

// Khởi tạo Database dạng JSON (hoạt động 100% trên mọi môi trường Node.js)
const DB_FILE = path.resolve(__dirname, 'licenses_data.json');

function readData() {
    try {
        if (!fs.existsSync(DB_FILE)) {
            const initial = { keys: [] };
            fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
            return initial;
        }
        const raw = fs.readFileSync(DB_FILE, 'utf8');
        return JSON.parse(raw);
    } catch (e) {
        console.error("[-] Lỗi đọc database:", e);
        return { keys: [] };
    }
}

function writeData(data) {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
        return true;
    } catch (e) {
        console.error("[-] Lỗi ghi database:", e);
        return false;
    }
}

// Lưu trữ token đăng nhập trong RAM
const activeTokens = new Set();

// Middleware bảo vệ các API quản trị
function requireAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(401).json({ success: false, message: "Chưa đăng nhập!" });
    }
    const token = authHeader.replace('Bearer ', '').trim();
    if (activeTokens.has(token)) {
        return next();
    }
    return res.status(401).json({ success: false, message: "Phiên đăng nhập hết hạn!" });
}

// ==========================================
// 1. API ĐĂNG NHẬP / XÁC THỰC ADMIN
// ==========================================

app.post('/admin/api/login', (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USER && password === ADMIN_PASS) {
        const token = crypto.randomBytes(24).toString('hex');
        activeTokens.add(token);
        return res.json({ success: true, token, message: "Đăng nhập thành công!" });
    }
    return res.status(401).json({ success: false, message: "Sai tên đăng nhập hoặc mật khẩu!" });
});

app.post('/admin/api/logout', (req, res) => {
    const authHeader = req.headers['authorization'];
    if (authHeader) {
        const token = authHeader.replace('Bearer ', '').trim();
        activeTokens.delete(token);
    }
    res.json({ success: true });
});

// ==========================================
// 2. API QUẢN LÝ KEY (CẦN ĐĂNG NHẬP)
// ==========================================

app.get('/admin/api/keys', requireAuth, (req, res) => {
    const data = readData();
    res.json(data.keys);
});

app.post('/admin/api/keys/create', requireAuth, (req, res) => {
    const { note, durationDays, packageName, customKey } = req.body;
    const data = readData();

    let key = customKey && customKey.trim().length > 0 
        ? customKey.trim().toUpperCase() 
        : "VIP-" + crypto.randomBytes(4).toString('hex').toUpperCase();

    if (data.keys.some(k => k.key === key)) {
        return res.status(400).json({ success: false, message: `Mã Key '${key}' đã tồn tại!` });
    }

    const days = parseInt(durationDays) || 30;
    const createdAt = Date.now();
    const expiresAt = createdAt + (days * 24 * 60 * 60 * 1000);

    const newKeyItem = {
        key: key,
        note: note ? note.trim() : 'Khách hàng',
        package_name: packageName || 'VIP',
        device_id: null,
        created_at: createdAt,
        expires_at: expiresAt,
        is_active: 1
    };

    data.keys.unshift(newKeyItem);
    writeData(data);

    res.json({ success: true, key: newKeyItem });
});

app.post('/admin/api/keys/reset-device', requireAuth, (req, res) => {
    const { key } = req.body;
    const data = readData();
    const target = data.keys.find(k => k.key === key);
    if (target) {
        target.device_id = null;
        writeData(data);
        return res.json({ success: true });
    }
    res.status(404).json({ success: false, message: "Không tìm thấy key" });
});

app.post('/admin/api/keys/toggle-status', requireAuth, (req, res) => {
    const { key, isActive } = req.body;
    const data = readData();
    const target = data.keys.find(k => k.key === key);
    if (target) {
        target.is_active = isActive ? 1 : 0;
        writeData(data);
        return res.json({ success: true });
    }
    res.status(404).json({ success: false, message: "Không tìm thấy key" });
});

app.post('/admin/api/keys/delete', requireAuth, (req, res) => {
    const { key } = req.body;
    const data = readData();
    const initialLen = data.keys.length;
    data.keys = data.keys.filter(k => k.key !== key);
    if (data.keys.length !== initialLen) {
        writeData(data);
        return res.json({ success: true });
    }
    res.status(404).json({ success: false, message: "Không tìm thấy key" });
});

// ==========================================
// 3. API DÀNH CHO IPHONE / TWEAK (DYLIB)
// ==========================================

app.post('/api/verify', (req, res) => {
    const { key, deviceID } = req.body;

    if (!key || !deviceID) {
        return res.status(400).json({ 
            authorized: false, 
            message: "Thiếu mã Key hoặc Device ID thiết bị!" 
        });
    }

    const data = readData();
    const item = data.keys.find(k => k.key.toUpperCase() === key.trim().toUpperCase());

    if (!item) {
        return res.status(404).json({ 
            authorized: false, 
            message: "Key không chính xác hoặc không tồn tại!" 
        });
    }

    if (!item.is_active) {
        return res.status(403).json({ 
            authorized: false, 
            message: "Key này đã bị tạm khóa bởi quản trị viên!" 
        });
    }

    if (Date.now() > item.expires_at) {
        return res.status(403).json({ 
            authorized: false, 
            message: "Key đã hết hạn sử dụng!" 
        });
    }

    if (!item.device_id) {
        item.device_id = deviceID;
        writeData(data);
    } else if (item.device_id !== deviceID) {
        return res.status(403).json({ 
            authorized: false, 
            message: "Key đã được kích hoạt trên một iPhone khác!" 
        });
    }

    const remainingDays = Math.max(0, Math.ceil((item.expires_at - Date.now()) / (1000 * 60 * 60 * 24)));
    
    return res.json({
        authorized: true,
        message: `Kích hoạt thành công gói ${item.package_name}!`,
        packageName: item.package_name,
        expiresAt: item.expires_at,
        remainingDays: remainingDays,
        serverTime: Date.now()
    });
});

app.post('/api/sign-out', (req, res) => {
    const { key, deviceID } = req.body;
    const data = readData();
    const item = data.keys.find(k => k.key.toUpperCase() === key.trim().toUpperCase() && k.device_id === deviceID);
    if (item) {
        item.device_id = null;
        writeData(data);
        return res.json({ success: true, message: "Đã gỡ thiết bị thành công" });
    }
    return res.status(400).json({ success: false, message: "Không thể gỡ thiết bị" });
});

// Luôn gửi file index.html cho trang chủ
app.get('*', (req, res) => {
    const indexPath = path.resolve(__dirname, 'public', 'index.html');
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        res.status(404).send("Lỗi: Không tìm thấy file public/index.html. Hãy kiểm tra lại thư mục public trên GitHub!");
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[+] Server đang chạy tại cổng ${PORT}`);
});
