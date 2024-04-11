import express from "express";
import dotenv from "dotenv";
import fileUpload from "express-fileupload";
import cookieParser from "cookie-parser";
import db from "./utils/database.js";
import cloudinaryConnect from "./utils/cloudinary.js";
import cors from "cors";
import userRoute from "./routes/user.route.js";

dotenv.config({
  path: "./.env",
});

const app = express();

app.use(cookieParser());
app.use(express.json());

app.use(
  fileUpload({
    useTempFiles: true,
    tempFileDir: "/tmp/",
  })
);

app.use(
  cors({
    origin: "*",
    credentials: true,
  })
);

app.use("/api/v1/auth", userRoute);

app.get("/", (req, res) => {
  return res.json({
    success: true,
    message: "Your server is up and running....",
  });
});

const PORT = process.env.PORT || 9000;

app.listen(PORT, () => {
  console.log(`server started at ${PORT}`);
});

db();
cloudinaryConnect();
