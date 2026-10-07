import axios from "axios";
import https from "node:https";

const http = axios.create({
  httpsAgent: new https.Agent({ family: 4 })
});

export default http;
