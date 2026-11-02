const express = require("express");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const _ = require("lodash");

const app = express();

app.get("/orders/:id", async (req, res) => {
  jwt.verify(req.get("authorization"), process.env.JWT_SECRET);
  const { data } = await axios.get(`http://orders.internal/orders/${req.params.id}`);
  res.json(_.pick(data, ["id", "status", "total"]));
});

app.listen(3000);
