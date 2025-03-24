# 🔒 TLS Scanner

**TLS Scanner** is an AWS Lambda-based tool designed to perform large-scale scans of websites to identify cipher and certificate issues efficiently and cost-effectively.

---

## 🌟 Features

- **Scalable Scanning**: Leverages AWS Lambda and S3 services to conduct extensive scans without significant infrastructure overhead.
- **Cost-Effective**: Utilizes serverless architecture to minimize costs associated with large-scale scanning operations.
- **Automated Workflow**: Submits scan jobs via an API, processes them asynchronously, and stores results in S3 for easy retrieval.

---

## 🛠️ Components

1. **Lambda API (`lambda_tlsapi`)**: Handles incoming scan requests and dispatches them to the scanning Lambda function. Returns a UUID for tracking the scan job.

2. **Lambda Scanner (`lambda_tlsscan`)**: Executes the actual TLS scanning based on the job parameters and stores the results in an S3 bucket.

---

## 🚀 Getting Started

### Prerequisites

- **AWS Account**: Ensure you have an AWS account with permissions to create and manage Lambda functions and S3 buckets.
- **AWS CLI**: Install and configure the AWS Command Line Interface.
- **Python 3.x**: Required for developing and deploying the Lambda functions.

### Setup Instructions

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/ltdenard/tlsscanner.git
   cd tlsscanner
   ```

2. **Install Dependencies**:

   Navigate to each Lambda function directory and install the necessary Python packages:

   ```bash
   cd lambda_tlsapi
   make build-lambda-package
   cd ../lambda_tlsscan
   make build-lambda-package
   ```

3. **Deploy Lambda Functions**:

   Use AWS CLI or an infrastructure-as-code tool like AWS CloudFormation or Terraform to deploy the Lambda functions. Ensure that the necessary IAM roles and permissions are set up for the functions to interact with S3 and other AWS services.

4. **Configure API Gateway**:

   Set up an API Gateway to trigger the `lambda_tlsapi` function upon receiving scan requests. This setup allows external clients to initiate scans via HTTP requests.

5. **Set Up S3 Buckets**:

   Create an S3 bucket to store the scan results. Ensure that the Lambda functions have the appropriate permissions to read from and write to this bucket.

---

## 📝 Usage

1. **Submit a Scan Request**:

   Send a POST request to the API Gateway endpoint with the target website details:

   ```bash
   curl -X POST https://your-api-gateway-endpoint.amazonaws.com/prod/scan \
   -H 'Content-Type: application/json' \
   -d '{"url": "https://example.com"}'
   ```

   The API responds with a UUID to track the scan job.

2. **Retrieve Scan Results**:

   After the scan completes, access the results in the designated S3 bucket using the provided UUID:

   ```bash
   aws s3 cp s3://your-s3-bucket-name/results/UUID.json .
   ```

---

## 🤝 Contributing

Contributions are welcome! Feel free to fork the repository and submit pull requests.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

> **Note**: Ensure compliance with legal and ethical guidelines when performing security scans. Unauthorized scanning of systems without permission is prohibited.

