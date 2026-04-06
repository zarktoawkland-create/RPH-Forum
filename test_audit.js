const http = require('http');

function request(method, path, data, token) {
    return new Promise((resolve, reject) => {
        const url = new URL(path, 'http://localhost:9191');
        const options = {
            hostname: url.hostname,
            port: url.port,
            path: url.pathname + url.search,
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };
        if (token) {
            options.headers['Authorization'] = `Bearer ${token}`;
        }

        const req = http.request(options, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, data: JSON.parse(body) });
                } catch (e) {
                    resolve({ status: res.statusCode, data: body });
                }
            });
        });
        req.on('error', reject);
        if (data) req.write(JSON.stringify(data));
        req.end();
    });
}

async function test() {
    console.log('=== 测试 1: 管理员登录 ===');
    const loginRes = await request('POST', '/api/auth/login', { username: 'admin', password: '123456' });
    console.log('状态:', loginRes.status);
    console.log('响应:', JSON.stringify(loginRes.data, null, 2));
    const token = loginRes.data.token;
    console.log('Token:', token ? token.substring(0, 20) + '...' : '无');

    if (!token) {
        console.log('登录失败，停止测试');
        return;
    }

    console.log('\n=== 测试 2: 上传正常角色卡 ===');
    const normalCard = {
        name: '测试角色',
        description: '这是一个正常的测试角色卡',
        data: {
            name: '测试角色',
            description: '正常角色',
            personality: '友善'
        }
    };
    const uploadRes = await request('POST', '/api/cards', normalCard, token);
    console.log('状态:', uploadRes.status);
    console.log('响应:', JSON.stringify(uploadRes.data, null, 2));

    console.log('\n=== 测试 3: 上传含 XSS 的角色卡 (应该被拦截) ===');
    const xssCard = {
        name: '恶意角色',
        description: '这是一个<Script>alert(1)</Script>恶意角色',
        data: {
            name: '恶意角色',
            description: '<script>alert("xss")</script> 这是恶意内容',
            personality: '邪恶'
        }
    };
    const xssRes = await request('POST', '/api/cards', xssCard, token);
    console.log('状态:', xssRes.status);
    console.log('响应:', JSON.stringify(xssRes.data, null, 2));

    console.log('\n=== 测试 4: 上传含 JavaScript 协议链接 (应该被拦截) ===');
    const jsLinkCard = {
        name: '危险角色',
        description: '点击<a href="javascript:alert(1)">这里</a>',
        data: {
            name: '危险角色',
            description: '危险角色 <a href="javascript:void(0)">链接</a>',
            personality: '危险'
        }
    };
    const jsRes = await request('POST', '/api/cards', jsLinkCard, token);
    console.log('状态:', jsRes.status);
    console.log('响应:', JSON.stringify(jsRes.data, null, 2));

    console.log('\n=== 测试 5: 上传含事件处理的角色卡 (应该被拦截) ===');
    const eventCard = {
        name: '事件角色',
        description: '<img src=x onerror="alert(1)">',
        data: {
            name: '事件角色',
            description: '事件角色 <img src=x onerror=alert(1)>',
            personality: '特殊'
        }
    };
    const eventRes = await request('POST', '/api/cards', eventCard, token);
    console.log('状态:', eventRes.status);
    console.log('响应:', JSON.stringify(eventRes.data, null, 2));

    console.log('\n=== 测试 6: 上传含 DataURL 的角色卡 (应该被拦截) ===');
    const dataUrlCard = {
        name: 'DataURL角色',
        description: 'data:text/html,<script>alert(1)</script>',
        data: {
            name: 'DataURL角色',
            description: 'data:text/html,<script>alert(1)</script>',
            personality: '特殊'
        }
    };
    const dataUrlRes = await request('POST', '/api/cards', dataUrlCard, token);
    console.log('状态:', dataUrlRes.status);
    console.log('响应:', JSON.stringify(dataUrlRes.data, null, 2));
}

test().catch(console.error);
