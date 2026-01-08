const { ApolloServer, gql } = require('apollo-server');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const typeDefs = gql(fs.readFileSync('./schema.graphql', { encoding: 'utf-8' }));

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: 5432
});

const JWT_SECRET = process.env.JWT_SECRET || "supersecret";

const resolvers = {
  Query: {
    me: async (_, __, { user }) => user,
    userById: async (_, { id }) => {
      const res = await pool.query("SELECT id,name,email,phone,address,role FROM users WHERE id=$1", [id]);
      return res.rows[0];
    }
  },
  Mutation: {
    register: async (_, args) => {
      const hashed = await bcrypt.hash(args.password, 10);
      const res = await pool.query(
        "INSERT INTO users(name,email,password,phone,address) VALUES($1,$2,$3,$4,$5) RETURNING id,name,email,phone,address,role",
        [args.name, args.email, hashed, args.phone, args.address]
      );
      return res.rows[0];
    },
    login: async (_, { email, password }) => {
      const res = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
      const user = res.rows[0];
      if (!user) throw new Error("User not found");

      const valid = await bcrypt.compare(password, user.password);
      if (!valid) throw new Error("Wrong password");

      const token = jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: "1h" });

      return {
        token,
        user
      };
    }
  }
};

const server = new ApolloServer({
  typeDefs,
  resolvers,
  context: ({ req }) => {
    const auth = req.headers.authorization || "";
    if (auth.startsWith("Bearer ")) {
      const token = auth.replace("Bearer ", "");
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return { user: decoded };
      } catch (e) {
        return {};
      }
    }
    return {};
  }
});

server.listen({ port: 4001 }).then(({ url }) => {
  console.log(`User Service running at ${url}`);
});
