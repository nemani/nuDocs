# nuDocs

### Made by Arjun Nemani (20161027) for Principles of Information Security @ IIIT Hyderabad (Nov 2020)

### How to Run

- Install docker
- Install nucypher from pip
- run ursulas
  `nucypher ursula run --dev --federated-only --rest-port 11500 &`
  `nucypher ursula run --dev --federated-only --rest-port 11501 --teacher localhost:11501 &`

- run ipfs docker
  `docker run ipfs/go-ipfs`
- cd into cryptpad
- run `npm install`
- run `node server.js`

### Details

- nuCypher folder contains the code for running nucypher as a cli tool
- cryptpad contains the code for the website
