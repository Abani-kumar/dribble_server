import { v2 as cloudinary } from "cloudinary";

const cloudinaryConnect = async () => {
  try {
    await cloudinary.config({
      cloud_name: process.env.CLOUD_NAME,
      api_key: process.env.API_KEY,
      api_secret: process.env.API_SECRET,
    });
    console.log("cloudinary connected successfully");
  } catch (error) {
    console.log("cloudinary connection failed", error);
  }
};

export default cloudinaryConnect;
