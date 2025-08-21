

document.addEventListener('DOMContentLoaded', () => {
    // Replace with your actual Stripe publishable key
    const stripe = Stripe('pk_test_YOUR_PUBLISHABLE_KEY'); 

    const proBtn = document.getElementById('upgrade-to-pro-btn');
    const enterpriseBtn = document.getElementById('go-enterprise-btn');

    const createCheckoutSession = (priceId) => {
        return fetch('/create-checkout-session', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                priceId: priceId,
            }),
        }).then((response) => response.json());
    };

    proBtn.addEventListener('click', () => {
        // Replace with your actual Price ID for the Pro plan
        createCheckoutSession('price_12345').then((session) => {
            if (session.id) {
                stripe.redirectToCheckout({ sessionId: session.id });
            }
        });
    });

    enterpriseBtn.addEventListener('click', () => {
        // Replace with your actual Price ID for the Enterprise plan
        createCheckoutSession('price_67890').then((session) => {
            if (session.id) {
                stripe.redirectToCheckout({ sessionId: session.id });
            }
        });
    });
});

