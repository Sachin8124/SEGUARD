/**
 * SE-GUARD Dashboard Authentication Integration Example
 * Use this in your dashboard.html or dashboard JavaScript
 */

// ============================================================================
// 1. CHECK IF USER IS LOGGED IN (On Dashboard Load)
// ============================================================================
async function initDashboard() {
  // Check if token exists
  if (!seguardAuth.isLoggedIn()) {
    console.log("Not authenticated, redirecting to login...");
    window.location.href = '/';
    return;
  }

  // Show cached data instantly, then refresh profile in background.
  displayUserInfo();

  loadUserProfile()
    .then(() => displayUserInfo())
    .catch(console.error);
}

// Call on page load
document.addEventListener('DOMContentLoaded', initDashboard);

// ============================================================================
// 2. LOAD AND DISPLAY USER PROFILE
// ============================================================================
async function loadUserProfile() {
  const result = await seguardAuth.getProfile();
  
  if (result.success) {
    const user = result.data.user;
    const roleData = result.data.role_data;
    
    // Store in window for global access
    window.currentUser = user;
    window.currentRoleData = roleData;
    
    console.log('User Profile:', user);
    console.log('Role Data:', roleData);
    
    // Display user greeting
    document.getElementById('userGreeting').textContent = 
      `Welcome, ${user.firstName}!`;
    
    // Display role badge
    const roleEmoji = {
      'business': '🏢',
      'client': '🛍️',
      'freelancer': '💻'
    };
    document.getElementById('roleBadge').textContent = 
      `${roleEmoji[user.role] || '👤'} ${user.role.toUpperCase()}`;
    
    // Display login count & last login
    document.getElementById('loginCount').textContent = 
      `Logins: ${user.login_count}`;
    
    if (user.last_login_at) {
      const lastLogin = new Date(user.last_login_at).toLocaleDateString();
      document.getElementById('lastLogin').textContent = 
        `Last login: ${lastLogin}`;
    }
  } else {
    console.error('Failed to load profile:', result.error);
    seguardAuth.logout();
    window.location.href = '/';
  }
}

// ============================================================================
// 3. DISPLAY USER INFO IN UI
// ============================================================================
function displayUserInfo() {
  const user = window.currentUser || seguardAuth.getCurrentUser();
  
  if (!user) return;

  // Update header with user name
  const header = document.querySelector('.topbar-chip');
  if (header) {
    header.innerHTML = `
      <span style="font-size: 14px;">👤 ${user.firstName} ${user.lastName}</span>
      <span style="font-size: 10px; color: var(--muted);">@${user.email}</span>
    `;
  }

  // Update sidebar role selector
  const roleSelect = document.querySelector('.role-select');
  if (roleSelect) {
    roleSelect.value = user.role;
  }
}

// ============================================================================
// 4. SAVE ROLE-SPECIFIC DATA (Example: Business Profile)
// ============================================================================
async function saveBusinessProfile(data) {
  const authHeader = seguardAuth.getAuthHeader();
  
  try {
    const response = await fetch('/api/data/business', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...authHeader
      },
      body: JSON.stringify({
        shop_name: data.shopName,
        phone: data.phone,
        address: data.address,
        business_type: data.businessType,
        description: data.description,
        verified: data.verified || false
      })
    });

    const result = await response.json();
    
    if (result.status === 'ok') {
      console.log('Business profile saved:', result.id);
      showNotification('Profile saved successfully!', 'success');
      
      // Reload profile to see changes
      await loadUserProfile();
      return true;
    } else {
      showNotification(result.message || 'Failed to save', 'error');
      return false;
    }
  } catch (error) {
    console.error('Error saving business profile:', error);
    showNotification('Connection error', 'error');
    return false;
  }
}

// ============================================================================
// 5. RETRIEVE ROLE DATA (Example: Get All Client Data)
// ============================================================================
async function getClientData() {
  const authHeader = seguardAuth.getAuthHeader();
  
  try {
    const response = await fetch('/api/data/client?limit=50', {
      method: 'GET',
      headers: authHeader
    });

    const result = await response.json();
    
    if (result.status === 'ok') {
      console.log('Client data retrieved:', result.data);
      displayClientDataTable(result.data);
      return result.data;
    } else {
      console.error('Failed to fetch data:', result.message);
      return [];
    }
  } catch (error) {
    console.error('Error fetching client data:', error);
    return [];
  }
}

// ============================================================================
// 6. SAVE TO CUSTOM COLLECTION (Example: Save Product)
// ============================================================================
async function saveProduct(product) {
  const authHeader = seguardAuth.getAuthHeader();
  
  try {
    const response = await fetch('/api/collection/products', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...authHeader
      },
      body: JSON.stringify({
        product_name: product.name,
        price: product.price,
        category: product.category,
        description: product.description,
        in_stock: product.inStock,
        image_url: product.imageUrl
      })
    });

    const result = await response.json();
    
    if (result.status === 'ok') {
      console.log('Product saved:', result.id);
      showNotification('Product added!', 'success');
      return result.id;
    } else {
      showNotification(result.message || 'Failed to save', 'error');
      return null;
    }
  } catch (error) {
    console.error('Error saving product:', error);
    showNotification('Connection error', 'error');
    return null;
  }
}

// ============================================================================
// 7. GET CUSTOM COLLECTION DATA (Example: Retrieve Products)
// ============================================================================
async function getProducts() {
  const authHeader = seguardAuth.getAuthHeader();
  
  try {
    const response = await fetch('/api/collection/products?limit=100', {
      method: 'GET',
      headers: authHeader
    });

    const result = await response.json();
    
    if (result.status === 'ok') {
      console.log('Products retrieved:', result.data);
      displayProductsTable(result.data);
      return result.data;
    } else {
      console.error('Failed to fetch products:', result.message);
      return [];
    }
  } catch (error) {
    console.error('Error fetching products:', error);
    return [];
  }
}

// ============================================================================
// 9. LOGOUT HANDLER
// ============================================================================
async function handleLogout() {
  const result = await seguardAuth.logout();
  
  if (result.success) {
    console.log('Logged out successfully');
    window.location.href = '/';
  } else {
    console.error('Logout error:', result.error);
    // Force clear anyway
    localStorage.clear();
    window.location.href = '/';
  }
}

// ============================================================================
// 10. HELPER: SHOW NOTIFICATIONS
// ============================================================================
function showNotification(message, type = 'info') {
  // Create notification element
  const notif = document.createElement('div');
  notif.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    padding: 16px 24px;
    border-radius: 8px;
    font-size: 14px;
    z-index: 9999;
    animation: slideIn 0.3s ease;
    ${type === 'success' ? 'background: #00ff88; color: #000;' : 
      type === 'error' ? 'background: #ff3355; color: #fff;' :
      'background: #0080ff; color: #fff;'}
  `;
  notif.textContent = message;
  document.body.appendChild(notif);

  // Auto-remove after 3 seconds
  setTimeout(() => {
    notif.style.animation = 'slideOut 0.3s ease';
    setTimeout(() => notif.remove(), 300);
  }, 3000);
}

// ============================================================================
// 11. DISPLAY DATA TABLE (Example: Business Data)
// ============================================================================
function displayClientDataTable(data) {
  const table = document.getElementById('clientDataTable');
  if (!table) return;

  let html = `
    <table style="width: 100%; border-collapse: collapse;">
      <thead>
        <tr style="background: var(--surface2);">
          <th style="padding: 12px; text-align: left; border-bottom: 1px solid var(--border);">Field</th>
          <th style="padding: 12px; text-align: left; border-bottom: 1px solid var(--border);">Value</th>
          <th style="padding: 12px; text-align: left; border-bottom: 1px solid var(--border);">Saved At</th>
        </tr>
      </thead>
      <tbody>
  `;

  data.forEach(record => {
    const savedTime = new Date(record.timestamp).toLocaleDateString();
    html += `
      <tr style="border-bottom: 1px solid var(--border);">
        <td style="padding: 12px;">Phone</td>
        <td style="padding: 12px;">${record.phone || '-'}</td>
        <td style="padding: 12px;">${savedTime}</td>
      </tr>
      <tr style="border-bottom: 1px solid var(--border);">
        <td style="padding: 12px;">Address</td>
        <td style="padding: 12px;">${record.address || '-'}</td>
        <td style="padding: 12px;">${savedTime}</td>
      </tr>
      <tr style="border-bottom: 1px solid var(--border);">
        <td style="padding: 12px;">Type</td>
        <td style="padding: 12px;">${record.business_type || '-'}</td>
        <td style="padding: 12px;">${savedTime}</td>
      </tr>
    `;
  });

  html += `
      </tbody>
    </table>
  `;

  table.innerHTML = html;
}

// ============================================================================
// 12. EXAMPLE: Form Submission to Save Profile
// ============================================================================
document.addEventListener('DOMContentLoaded', function() {
  const profileForm = document.getElementById('businessProfileForm');
  
  if (profileForm) {
    profileForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const formData = {
        shopName: document.getElementById('shopName').value,
        phone: document.getElementById('phone').value,
        address: document.getElementById('address').value,
        businessType: document.getElementById('businessType').value,
        description: document.getElementById('description').value,
        verified: false
      };
      
      const success = await saveBusinessProfile(formData);
      
      if (success) {
        profileForm.reset();
      }
    });
  }
});

// ============================================================================
// 13. GET AUTHORIZATION HEADER FOR CUSTOM API CALLS
// ============================================================================
async function makeAuthenticatedRequest(endpoint, options = {}) {
  const authHeader = seguardAuth.getAuthHeader();
  
  try {
    const response = await fetch(endpoint, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...authHeader,
        ...options.headers
      }
    });

    return await response.json();
  } catch (error) {
    console.error('Request failed:', error);
    return { status: 'error', message: error.message };
  }
}

// Usage:
// const result = await makeAuthenticatedRequest('/api/some-endpoint', {
//   method: 'POST',
//   body: JSON.stringify({ data: 'value' })
// });

// ============================================================================
// EXPORT FUNCTIONS FOR USE IN OTHER FILES
// ============================================================================
// These are now available globally:
// - loadUserProfile()
// - displayUserInfo()
// - saveBusinessProfile()
// - getClientData()
// - saveProduct()
// - getProducts()
// - handleLogout()
// - makeAuthenticatedRequest()

function readFileAsDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

async function sendDashboardMessage() {
  const messageInput = document.getElementById('messageInput');
  const attachmentInput = document.getElementById('attachmentInput');

  if (!messageInput || !attachmentInput) {
    return;
  }

  const message = (messageInput.value || '').trim();
  const files = Array.from(attachmentInput.files || []);

  if (!message && files.length === 0) {
    alert('Please enter a message or attach a file.');
    return;
  }

  const attachmentPayload = [];
  for (const file of files.slice(0, 5)) {
    const dataUrl = await readFileAsDataUrl(file);
    attachmentPayload.push({
      name: file.name,
      size: `${Math.max(1, Math.round(file.size / 1024))} KB`,
      type: file.type || 'application/octet-stream',
      url: dataUrl,
    });
  }

  const authHeader = seguardAuth.getAuthHeader();

  try {
    const response = await fetch('/api/messages/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...authHeader,
      },
      body: JSON.stringify({
        receiver_id: window.currentChatPartner?.id || 'client_inbox',
        receiver_name: window.currentChatPartner?.name || 'User',
        message_text: message,
        attachments: attachmentPayload,
      }),
    });

    const result = await response.json();
    if (result.status === 'ok') {
      alert('Message sent successfully!');
      messageInput.value = '';
      attachmentInput.value = '';
    } else {
      alert(`Error: ${result.message}`);
    }
  } catch (error) {
    console.error('Failed to send message:', error);
    alert('Failed to send message. Please try again later.');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const sendButton = document.getElementById('sendButton');
  if (sendButton) {
    sendButton.addEventListener('click', sendDashboardMessage);
  }
});
