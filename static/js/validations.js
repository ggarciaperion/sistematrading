// static/js/validations.js - Validaciones comunes para todo el sistema
const Validations = {
    // Validar número de documento según tipo
    validateDocNumber: function(tipo, numero) {
        const lengths = { 
            'DNI': 8, 
            'Carnet de Extranjería': 9, 
            'RUC': 11 
        };
        const expectedLength = lengths[tipo];
        if (!expectedLength) return false;
        
        return numero.length === expectedLength && /^\d+$/.test(numero);
    },
    
    // Validar teléfono
    validatePhone: function(telefono) {
        return /^\d{7,15}$/.test(telefono);
    },
    
    // Validar email
    validateEmail: function(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    },
    
    // Validar monto numérico
    validateAmount: function(monto) {
        const num = parseFloat(monto);
        return !isNaN(num) && num > 0;
    },
    
    // Formatear número con separadores de miles
    formatNumber: function(num, decimals = 2, isCurrency = false) {
        const fixedNum = parseFloat(num).toFixed(decimals);
        const parts = fixedNum.split('.');
        parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        return isCurrency ? parts.join('.') : parts.join('.');
    },
    
    // Sanitizar entrada de texto
    sanitizeText: function(text) {
        return text.trim().replace(/[<>]/g, '');
    },
    
    // Validar y formatear DNI
    formatDNI: function(dni) {
        const cleanDNI = dni.replace(/\D/g, '').slice(0, 8);
        return cleanDNI;
    }
};

// Auto-inicialización de validaciones en campos comunes
$(document).ready(function() {
    // Aplicar validaciones a campos de DNI
    $('input[name="dni"], input[name="doc_number"]').on('input', function() {
        this.value = this.value.replace(/\D/g, '').slice(0, 8);
    });
    
    // Aplicar validaciones a campos de teléfono
    $('input[name="phone"]').on('input', function() {
        this.value = this.value.replace(/\D/g, '').slice(0, 15);
    });
    
    // Aplicar mayúsculas a nombres
    $('input[name="name"], input[name="nombres"]').on('input', function() {
        this.value = this.value.toUpperCase();
    });
});

// Exportar para uso en otros archivos
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Validations;
}