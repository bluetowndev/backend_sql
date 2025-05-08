import express from "express"
import "dotenv/config"
import routes from "./routes/index.js"
import cors from "cors";
// import bodyParser from "body-parser";

const app= express();
const PORT= process.env.PORT || 5000;

// app.use(bodyParser.json({ limit: '10mb' }));
// app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));

const allowedOrigins = [
    // 'https://frontend-09jj.onrender.com', // Production frontend URL
    'http://localhost:3000', // Local development frontend URL
    'exp://192.168.1.34:8081',
    'http://192.168.1.34:4000'
  ];
  
  app.use(cors({
    origin: function (origin, callback) {
      if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true
  }));

app.use(express.json());
app.use(express.urlencoded({extended:false}))

app.use((req, res, next) => {
    console.log(req.path, req.method);
    next();
  });

app.get("/", (req, res)=>{
    return res.send("Hi there!");
})

app.use(routes);

app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({
      success: false,
      message: 'Request payload too large. Please reduce the image size.',
    });
  }
  console.error(err.stack);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

app.listen(PORT, ()=>{
    console.log(`Server listening at port ${PORT} succesfully`)
})