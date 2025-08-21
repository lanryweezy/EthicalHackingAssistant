
const express = require('express');
const app = express();
const stripe = require('stripe')('sk_test_YOUR_SECRET_KEY'); // Replace with your actual secret key

app.use(express.static('landing-page'));
app.use(express.json());

app.post('/create-checkout-session', async (req, res) => {
    const { priceId } = req.body;

    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [
                {
                    price: priceId,
                    quantity: 1,
                },
            ],
            mode: 'subscription',
            success_url: `${req.headers.origin}/success.html?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${req.headers.origin}/cancel.html`,
        });

        res.json({ id: session.id });
    } catch (error) {
        res.status(400).json({ error: { message: error.message } });
    }
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});

