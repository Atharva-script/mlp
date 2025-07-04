// server.mjs
const { createServer } = require('node:http');

const app = require('./app'); // Import the Express app

const server = createServer(app);

const PORT = process.env.PORT || 3001;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Listening on 0.0.0.0:${PORT}`);
});