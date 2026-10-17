/* ============================================
   User Control — JavaScript приложение
   ============================================ */

const App = {
    refreshInterval: null,
    refreshDelay: 10000,
    currentPage: '',

    init() {
        this.updateClock();
        setInterval(() => this.updateClock(), 1000);
        this.loadAlertCount();
        setInterval(() => this.loadAlertCount(), 15000);

        const autoRefreshEl = document.getElementById('autoRefresh');
        if (autoRefreshEl) {
            autoRefreshEl.addEventListener('change', () => {
                if (autoRefreshEl.checked) {
                    this.startAutoRefresh();
                } else {
                    this.stopAutoRefresh();
                }
            });
        }

        this.startAutoRefresh();
    },

    updateClock() {
        const el = document.getElementById('currentTime');
        if (el) {
            const now = new Date();
            el.textContent = now.toLocaleString('ru-RU', {
                year: 'numeric', month: '2-digit', day: '2-digit',
                hour: '2-digit', minute: '2-digit', second: '2-digit'
            });
        }
    },

    startAutoRefresh() {
        this.stopAutoRefresh();
        this.refreshInterval = setInterval(() => {
            if (typeof refreshData === 'function') {
                refreshData();
            }
        }, this.refreshDelay);
    },

    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    },

    async loadAlertCount() {
        try {
            const resp = await fetch('/api/alerts?unread=true&limit=1');
            const data = await resp.json();
            const badge = document.getElementById('alertBadge');
            if (badge) {
                const count = data.length;
                if (count > 0) {
                    badge.textContent = count > 99 ? '99+' : count;
                    badge.style.display = 'inline';
                } else {
                    badge.style.display = 'none';
                }
            }
        } catch (e) {
            console.error('Ошибка загрузки оповещений:', e);
        }
    },

    toast(title, message, type = 'info') {
        const container = document.getElementById('toastContainer');
        if (!container) return;

        const icons = {
            critical: '🔴',
            warning: '🟡',
            info: '🔵',
            success: '🟢'
        };

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <span class="toast-icon">${icons[type] || '🔵'}</span>
            <div class="toast-content">
                <div class="toast-title">${this.escapeHtml(title)}</div>
                <div class="toast-message">${this.escapeHtml(message)}</div>
            </div>
        `;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.animation = 'slideOut 0.3s ease forwards';
            setTimeout(() => toast.remove(), 300);
        }, 5000);
    },

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    async fetchJson(url) {
        try {
            const resp = await fetch(url);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            return await resp.json();
        } catch (e) {
            console.error(`Fetch error: ${url}`, e);
            return null;
        }
    },

    async acknowledgeAlert(alertId) {
        try {
            await fetch(`/api/alerts/${alertId}/acknowledge`, { method: 'POST' });
            this.loadAlertCount();
            if (typeof refreshData === 'function') refreshData();
        } catch (e) {
            console.error('Ошибка подтверждения:', e);
        }
    },

    async acknowledgeAll() {
        try {
            const alerts = await this.fetchJson('/api/alerts?unread=true&limit=1000');
            if (alerts) {
                for (const a of alerts) {
                    await fetch(`/api/alerts/${a.id}/acknowledge`, { method: 'POST' });
                }
                this.loadAlertCount();
                if (typeof refreshData === 'function') refreshData();
            }
        } catch (e) {
            console.error('Ошибка подтверждения всех:', e);
        }
    },

    exportCsv(table) {
        window.open(`/api/export/csv/${table}`, '_blank');
    },

    formatNumber(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
        return String(n);
    },

    formatDate(str) {
        if (!str) return '—';
        const d = new Date(str);
        return d.toLocaleString('ru-RU');
    },

    truncate(str, len = 100) {
        if (!str) return '';
        return str.length > len ? str.substring(0, len) + '…' : str;
    }
};

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('collapsed');
}

// Инициализация при загрузке
document.addEventListener('DOMContentLoaded', () => App.init());